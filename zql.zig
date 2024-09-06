const heap = @import("std").heap;
const MultiArrayList = @import("std").MultiArrayList;
const assert = @import("std").debug.assert;
const fmt = @import("std").fmt;
const panic = @import("std").debug.panic;
const StaticStringMap = @import("std").StaticStringMapWithEql;
const eqlLenIgnoreCase = @import("std").static_string_map.eqlAsciiIgnoreCase;
const eql = @import("std").mem.eql;
const ArrayListUnmanaged = @import("std").ArrayListUnmanaged;
const Allocator = @import("std").mem.Allocator;
const maxInt = @import("std").math.maxInt;

// (arrayPointer: i32, length: i32)
extern fn print(ptr: [*]const u8, len: usize) void;

extern fn readBuffer(ptr: [*]const u8, offset: usize, len: usize) void;

export fn malloc(size: usize) ?*u8 {
    const page_allocator = heap.page_allocator;
    const mem = page_allocator.alloc(u8, size) catch null;
    if (mem == null) {
        return null;
    }
    return @ptrCast(mem);
}

fn valFromSlice(comptime T: type, slice: []u8) T {
    const result: *align(1) T = @ptrCast(slice[0..@sizeOf(T)]);
    return result.*;
}

// SQLite stores the header in big-endian format
const sqlite_header_size = 100;
const SQLiteDbHeader = extern struct {
    header_string: [16]u8,
    page_size: u16,
    file_format_write_version: u8,
    file_format_read_version: u8,
    reserved_space: u8,
    max_payload_fraction: u8,
    min_payload_fraction: u8,
    leaf_payload_fraction: u8,
    file_change_counter: u32,
    database_size: u32,
    first_freelist_trunk_page: u32,
    total_freelist_pages: u32,
    schema_cookie: u32,
    schema_format_number: u32,
    default_page_cache_size: u32,
    largest_btree_page_number: u32,
    database_text_encoding: u32,
    user_version: u32,
    incremental_vacuum_mode: u32,
    application_id: u32,
    reserved: [20]u8,
    version_valid_for: u32,
    sqlite_version_number: u32,

    pub fn get_page_size(self: *SQLiteDbHeader) u16 {
        return @byteSwap(self.page_size);
    }

    pub fn get_version(self: *SQLiteDbHeader) u32 {
        return @byteSwap(self.sqlite_version_number);
    }
};

const sqlite_bt_header_size = 12;
const SQLiteBtHeader = extern struct {
    metadata: [8]u8,
    // // Doesn't exist on leaf pages (0x0D and 0x0A page_type)
    right_child_page: u32,

    pub fn from(buffer: []u8) *SQLiteBtHeader {
        return @alignCast(@ptrCast(buffer[0..sqlite_bt_header_size])); // TODO: align(1)?
    }

    pub fn get_cell_addr(self: *SQLiteBtHeader, buffer: []u8, index: u32) u16 {
        const bt_header_size = self.get_header_size();
        const start = bt_header_size + (index * 2);
        const cell_adr: u16 = @byteSwap(valFromSlice(u16, buffer[start .. start + 2]));
        debug("cell adr: {d}", .{cell_adr});
        return cell_adr;
    }

    pub fn get_header_size(self: *SQLiteBtHeader) u8 {
        const page_type = self.get_page_type();
        debug("page type: {x}", .{page_type});
        switch (page_type) {
            0x0D, 0x0A => {
                return 8;
            },
            else => {
                return 12;
            },
        }
    }

    pub fn get_page_type(self: *SQLiteBtHeader) u8 {
        return self.metadata[0];
    }

    pub fn get_first_freeblock(self: *SQLiteBtHeader) u16 {
        var block: u16 = 0;
        block = @as(u16, self.metadata[1]) << 8;
        block |= self.metadata[2];
        return block;
    }

    pub fn get_cell_count(self: *SQLiteBtHeader) u16 {
        var block: u16 = 0;
        block = @as(u16, self.metadata[3]) << 8;
        block |= self.metadata[4];
        return block;
    }

    pub fn get_cell_offset(self: *SQLiteBtHeader) u16 {
        var block: u16 = 0;
        block = @as(u16, self.metadata[5]) << 8;
        block |= self.metadata[6];
        return block;
    }

    pub fn get_fragment_count(self: *SQLiteBtHeader) u8 {
        return self.metadata[7];
    }

    pub fn get_right_child_page(self: *SQLiteBtHeader) u32 {
        assert(self.get_page_type() != 0x0D and self.get_page_type() != 0x0A);
        return @byteSwap(self.right_child_page);
    }
};

// Bit masks for get_varint
const bits_7 = 0x7f;
const slot_2_0 = (0x7f << 14) | 0x7f;
const slot_4_2_0 = (0x7f << 28) | slot_2_0;

// max 64 bit value
const max_64_bit = 0xFFFFFFFF_FFFFFFFF;

const one_kb = 1024;
const query_buffer_size = 512;
const memory_buffery_size = 32 * one_kb;
var query_buf: [query_buffer_size:0]u8 = undefined;
var memory_buf: [memory_buffery_size]u8 = undefined;

comptime {
    assert(@sizeOf(SQLiteDbHeader) == sqlite_header_size);
    assert(@sizeOf(SQLiteBtHeader) == sqlite_bt_header_size);
}

fn debug(comptime format: []const u8, args: anytype) void {
    var buf: [500]u8 = undefined;
    const line = fmt.bufPrint(&buf, format, args) catch l: {
        buf[buf.len - 3 ..][0..3].* = "...".*;
        break :l &buf;
    };
    print(line.ptr, line.len);
}

fn get_varint(ptr1: [*]u8, result: *u64) u8 {
    var a: u32 = undefined;
    var b: u32 = undefined;
    var ptr: [*]u8 = ptr1;

    if (@as(i8, @bitCast(ptr[0])) >= 0) {
        result.* = ptr[0];
        return 1;
    }

    if (@as(i8, @bitCast(ptr[1])) >= 0) {
        result.* = ((ptr[0] & bits_7) << 7) | ptr[1];
        return 2;
    }

    a = ptr[0];
    a = a << 14;
    // a = ptr[0] << 14;
    b = ptr[1];
    ptr += 2;
    a |= ptr[0];

    if ((a & 0x80) == 0) {
        a &= slot_2_0;
        b &= bits_7;
        b = b << 7;
        a |= b;
        result.* = a;
        return 3;
    }

    a &= slot_2_0;
    ptr += 1;
    b = b << 14;
    b |= ptr[0];

    if ((b & 0x80) == 0) {
        b &= slot_2_0;
        a = a << 7;
        a |= b;
        result.* = a;
        return 4;
    }

    // TODO: values up to 9 bytes
    debug("uh oh I pwanic -><- uwu ", .{});
    panic("uh oh I pwanic -><- uwu ", .{});
}

const TokenType = enum {
    number,
    plus,
    minus,
    asterisk,
    divide,
    lparen,
    rparen,
    eof,
    semicolon,
    gt,
    gte,
    lt,
    lte,
    eq,
    ne,
    comma,
    integer,
    float,
    single_quote_word,
    double_quote_word,
    word,
    keyword_create,
    keyword_table,
    keyword_integer,
    keyword_primary,
    keyword_key,
    keyword_text,
    keyword_select,
    keyword_from,
    keyword_where,
    keyword_and,
    keyword_or,
    invalid,

    pub fn lexeme(token_type: TokenType) ?[]const u8 {
        return switch (token_type) {
            .asterisk => "*",
            .comma => ",",
            .eq => "=",
            .lparen => "(",
            .ne => "!=",
            .rparen => ")",
            .semicolon => ";",
            .keyword_and => "AND",
            .keyword_create => "CREATE",
            .keyword_from => "FROM",
            .keyword_integer => "INTEGER",
            .keyword_key => "KEY",
            .keyword_or => "OR",
            .keyword_primary => "PRIMARY",
            .keyword_select => "SELECT",
            .keyword_table => "TABLE",
            .keyword_text => "TEXT",
            .keyword_where => "WHERE",
            else => null,
        };
    }
};

const Token = struct {
    type: TokenType,
    location: idx,

    const idx = struct {
        start: u32,
        end: u32,
    };

    pub fn getKeyword(bytes: []const u8) ?TokenType {
        return keywords.get(bytes);
    }

    pub const keywords = StaticStringMap(TokenType, eqlLenIgnoreCase).initComptime(.{
        .{ "and", TokenType.keyword_and },
        .{ "create", TokenType.keyword_create },
        .{ "from", TokenType.keyword_from },
        .{ "integer", TokenType.keyword_integer },
        .{ "key", TokenType.keyword_key },
        .{ "or", TokenType.keyword_or },
        .{ "primary", TokenType.keyword_primary },
        .{ "select", TokenType.keyword_select },
        .{ "table", TokenType.keyword_table },
        .{ "text", TokenType.keyword_text },
        .{ "where", TokenType.keyword_where },
    });
};

const Tokenizer = struct {
    buffer: [:0]const u8,
    index: usize,

    const State = enum {
        asterisk,
        double_quote_word,
        float,
        identifier,
        int,
        semicolon,
        single_quote_word,
        start,
    };

    pub fn from(buffer: [:0]const u8, index: usize) Tokenizer {
        return Tokenizer{
            .buffer = buffer,
            .index = index,
        };
    }

    pub fn ingest(self: *Tokenizer, alloc: Allocator, token_list: *TokenList) Error!void {
        while (true) {
            var token = self.next();
            try token_list.append(alloc, .{
                .tag = token.type,
                .start = token.location.start,
            });
            if (token.type == TokenType.eof) {
                break;
            }

            // debugging
            self.dump(&token);
        }
    }

    pub fn dump(self: *Tokenizer, token: *Token) void {
        if (token.type.lexeme()) |word| {
            print(word.ptr, word.len);
        } else {
            debug("[{d}]: {s}", .{ token.location.start, self.buffer[token.location.start..token.location.end] });
        }
    }

    pub fn next(self: *Tokenizer) Token {
        var state: State = .start;
        var token: Token = .{
            .type = TokenType.eof,
            .location = .{ .start = self.index, .end = 0 },
        };

        while (true) : (self.index += 1) {
            const c = self.buffer[self.index];
            switch (state) {
                .start => switch (c) {
                    0 => {
                        break;
                    },
                    'a'...'z', 'A'...'Z' => {
                        state = .identifier;
                    },
                    '0'...'9' => {
                        state = .int;
                    },
                    ' ', '\n' => {
                        token.location.start = self.index + 1;
                    },
                    '"' => {
                        state = .double_quote_word;
                    },
                    ';' => {
                        token.type = .semicolon;
                        self.index += 1;
                        break;
                    },
                    '*' => {
                        token.type = .asterisk;
                        self.index += 1;
                        break;
                    },
                    '(' => {
                        token.type = .lparen;
                        self.index += 1;
                        break;
                    },
                    ')' => {
                        token.type = .rparen;
                        self.index += 1;
                        break;
                    },
                    ',' => {
                        token.type = .comma;
                        self.index += 1;
                        break;
                    },
                    else => {
                        token.type = .invalid;
                        token.location.end = self.index;
                        self.index += 1;
                        return token;
                    },
                },
                .identifier => switch (c) {
                    'a'...'z', 'A'...'Z' => {},
                    else => {
                        if (Token.getKeyword(self.buffer[token.location.start..self.index])) |token_type| {
                            token.type = token_type;
                        } else {
                            token.type = TokenType.word;
                        }
                        break;
                    },
                },
                .int => switch (c) {
                    '0'...'9' => {},
                    '.' => {
                        state = .float;
                    },
                    else => {
                        token.type = TokenType.integer;
                        break;
                    },
                },
                .double_quote_word => switch (c) {
                    'a'...'z', 'A'...'Z' => {},
                    '"' => {
                        token.type = TokenType.double_quote_word;
                        break;
                    },
                    else => {
                        token.type = TokenType.invalid;
                    },
                },
                .float => switch (c) {
                    '0'...'9' => {},
                    else => {
                        token.type = TokenType.float;
                        break;
                    },
                },
                else => {
                    break;
                },
            }
        }

        if (token.type == TokenType.eof) {
            token.location.start = self.index;
        }

        token.location.end = self.index;
        return token;
    }
};

const Expr = struct {
    // Expr uses Element struct, value is val, tag is type of comparison, and data lhs rhs is the left right linked
    // expressions for and or. Literal comparison has the column id in the lhs
    index: u32,
};

const SelectStmt = struct {
    columns: u64, // Each bit represents one column in the table TODO: support tables with more than 64 columns
    table: TableStmt,
    where: ?Expr,
};

const ElementType = enum {
    compare_and,
    compare_eq_float,
    compare_eq_int,
    compare_eq_str,
    compare_ne_float,
    compare_ne_int,
    compare_ne_str,
    compare_or,
    expr_group,
    integer,
    table,
    text,
};

const Element = struct {
    value: union {
        str: String,
        int: i64,
        float: f64,
    },
    tag: ElementType,
    data: Data,
};

const Data = struct {
    lhs: u32,
    rhs: u32,
};

const TableStmt = struct {
    name: String,
    first_column: u32,
    page: u32,

    // primary key is always in the first column of the table
    pub fn getPrimaryKey(self: *TableStmt) u32 {
        return self.first_column;
    }

    // TODO: benchmark to see if a hash table or getting the slices of the element list will speed this up
    pub fn getColumnIndex(self: *const TableStmt, list: *ElementList, name: []const u8) ?u32 {
        var index: u32 = self.first_column;
        var col_count: u32 = 0;
        while (index < list.len) : (col_count += 1) {
            const col = list.get(index);
            if (eql(u8, name, col.value.str.str())) {
                return col_count;
            }
            index = col.data.lhs;
        }
        return null;
    }

    pub fn from(elem: Element) TableStmt {
        assert(elem.tag == ElementType.table);
        return .{ .name = elem.value.str, .first_column = elem.data.lhs, .page = elem.data.rhs };
    }
};

const Inst = struct {
    opcode: Opcode,
    p1: u32,
    p2: u32,
    p3: u32,
    p4: u64, // p4 seems optional, only some instructions have it? We can do the same
    p5: u16,
};

const Opcode = enum(u8) {
    init,
    open_read,
    rewind,
    row_id,
    column,
    result_row,
    next,
    halt,
    transaction,
    goto,
};

const Register = union(enum) {
    none,
    int: i64,
    float: f64,
    str: []u8,
    binary: []u8,

    pub fn from_column(column: SQLiteColumn) Register {
        switch (column) {
            .i8, .i16, .i24, .i32, .i48, .i64 => return .{ .int = column.getInt().? },
            .value_0 => return .{ .int = 0 },
            .value_1 => return .{ .int = 1 },
            .f64 => return .{ .float = column.f64 },
            .empty => return Register.none,
            .invalid => {
                debug("invalid SQLiteColumn when converting to register", .{});
                return Register.none;
            },
            .blob => return .{ .binary = column.blob },
            .text => return .{ .str = column.text },
        }
    }

    pub fn to_str(self: Register, buffer: []u8) anyerror![]u8 {
        return switch (self) {
            .none => try fmt.bufPrint(buffer, "[null]", .{}),
            .int => try fmt.bufPrint(buffer, "{d}", .{self.int}),
            .float => try fmt.bufPrint(buffer, "{e}", .{self.float}),
            .str => try fmt.bufPrint(buffer, "{s}", .{self.str}),
            .binary => try fmt.bufPrint(buffer, "[binary]", .{}),
        };
    }
};

const SQLiteDbTable = struct {
    page: u32,
    sql: String,
};

const SQLiteRecord = struct {
    buffer: []u8,
    row_id: u64,
    size: u32,
    header_size: u32,
    cursor: u32,
    header_cursor: u32,

    // header comes first with column data types. Header starts with size of header varint.
    // values come after, size of ea determined by respective header

    pub fn from(buffer: []u8) SQLiteRecord {
        var cell_size: u64 = 0;
        var cell_header_size: u64 = 0;
        var cursor: u32 = 0;
        var cell_header_int: u32 = 0;
        var row_id: u64 = 0;

        // TODO: this only supports 0x0d pages. Support the other pages
        cursor += get_varint(buffer.ptr, &cell_size);
        cursor += get_varint(buffer.ptr + cursor, &row_id);
        cell_header_int += get_varint(buffer.ptr + cursor, &cell_header_size);

        cell_header_size -= cell_header_int;
        cell_size -= cell_header_int;
        cursor += cell_header_int;

        // TODO: extra validation to make sure its 32 bit size?
        return SQLiteRecord{
            .buffer = buffer[cursor..],
            .row_id = row_id,
            .size = @intCast(cell_size),
            .header_size = @intCast(cell_header_size),
            .cursor = @intCast(cell_header_size),
            .header_cursor = 0,
        };
    }

    pub fn reset(self: *SQLiteRecord) void {
        self.cursor = self.header_size;
        self.header_cursor = 0;
    }

    pub fn next(self: *SQLiteRecord) ?SQLiteColumn {
        if (self.cursor >= self.size) return null;
        if (self.header_cursor >= self.header_size) {
            self.header_cursor = 0;
        }
        var header_val: u64 = 0;
        self.header_cursor += get_varint(self.buffer.ptr + self.header_cursor, &header_val);

        const size: u32 = @truncate(SQLiteColumn.size(header_val));

        const result = SQLiteColumn.from(
            header_val,
            self.buffer[self.cursor..],
        );

        debug("next() size: {d} col_type: {s}", .{ size, @tagName(result) });

        self.cursor += size;
        return result;
    }

    pub fn consume(self: *SQLiteRecord) void {
        if (self.cursor >= self.size) return;
        if (self.header_cursor >= self.header_size) {
            self.header_cursor = 0;
        }
        var header_val: u64 = 0;
        self.header_cursor += get_varint(self.buffer.ptr + self.header_cursor, &header_val);

        // for debugging
        // const size: u32 = @truncate(SQLiteColumnType.size(header_val));
        // const col_type = SQLiteColumnType.from(header_val);
        // debug("next() size: {d} col_type: {}", .{ size, col_type });

        self.cursor += @truncate(SQLiteColumn.size(header_val));
    }
};

const SQLiteColumn = union(enum) {
    empty: void,
    i8: i8,
    i16: i16,
    i24: i24,
    i32: i32,
    i48: i48,
    i64: i64,
    f64: f64,
    value_0: void,
    value_1: void,
    invalid: void,
    blob: []u8,
    text: []u8,

    pub fn from(header_int: u64, buffer: []u8) SQLiteColumn {
        switch (header_int) {
            0 => {
                return SQLiteColumn.empty;
            },
            1 => {
                return .{ .i8 = @intCast(buffer[0]) };
            },
            2 => {
                return .{ .i16 = @byteSwap(valFromSlice(i16, buffer)) };
            },
            3 => {
                return .{ .i24 = @byteSwap(valFromSlice(i24, buffer)) };
            },
            4 => {
                return .{ .i32 = @byteSwap(valFromSlice(i32, buffer)) };
            },
            5 => {
                return .{ .i48 = @byteSwap(valFromSlice(i48, buffer)) };
            },
            6 => {
                return .{ .i64 = @byteSwap(valFromSlice(i64, buffer)) };
            },
            7 => {
                const result = valFromSlice(u64, buffer);
                return .{ .f64 = @floatFromInt(@byteSwap(result)) };
            },
            8 => {
                return SQLiteColumn.value_0;
            },
            9 => {
                return SQLiteColumn.value_1;
            },
            10, 11 => {
                return SQLiteColumn.invalid;
            },
            else => {
                const buffer_size: u32 = @truncate(SQLiteColumn.size(header_int));
                if (header_int % 2 == 0) {
                    return .{ .blob = buffer[0..buffer_size] };
                }
                return .{ .text = buffer[0..buffer_size] };
            },
        }
    }

    pub fn getInt(self: SQLiteColumn) ?i64 {
        switch (self) {
            .i8 => return self.i8,
            .i16 => return self.i16,
            .i24 => return self.i24,
            .i32 => return self.i32,
            .i48 => return self.i48,
            .i64 => return self.i64,
            else => return null,
        }
    }

    pub fn size(val: u64) u64 {
        switch (val) {
            0, 8, 9, 10, 11 => return 0,
            1 => return 1,
            2 => return 2,
            3 => return 3,
            4 => return 4,
            5 => return 6,
            6, 7 => return 8,
            else => {
                if (val % 2 == 0) {
                    // Divide by 2 (>> 1). Compiler should be smart enough to optimize /, but I'm smart too
                    return (val - 12) / 2;
                }
                return (val - 13) / 2;
            },
        }
    }
};

pub const Error = error{ InvalidBinary, InvalidSyntax, OutOfMemory };

const Db = struct {
    cursor: usize, // TODO: use this?
    buffer: []u8,
    page_size: u16,

    pub fn from(buffer: []u8) Error!Db {
        if (buffer.len < @sizeOf(SQLiteDbHeader)) {
            debug("buffer too small.", .{});
            return error.InvalidBinary;
        }
        const header: *SQLiteDbHeader = @alignCast(@ptrCast(buffer[0..sqlite_header_size]));
        const page_size = header.get_page_size();
        debug("page_size: {d}", .{page_size});
        return Db{
            .cursor = 0,
            .buffer = buffer,
            .page_size = page_size,
        };
    }

    pub fn readPage(self: *Db, index: u32) []u8 {
        debug("index: {d}, page_size: {d}", .{ index, self.page_size });
        const page_start: u32 = index * self.page_size;
        debug("page start {x}", .{page_start});
        if (self.buffer.len <= page_start) {
            // TODO: buffer management (alloc?)
            debug("increasing buffer size", .{});
            const length = page_start + self.page_size;
            readBuffer(self.buffer.ptr, 0, length);
            const new_slice = self.buffer.ptr[0..length]; // first page
            self.buffer = new_slice;
            debug("allocated", .{});
        }
        debug("buffer len: {d}, page_start: {d}", .{ self.buffer.len, page_start });
        return self.buffer[page_start..];
    }

    // Table schema:
    // CREATE TABLE sqlite_schema(
    //   type text,
    //   name text,
    //   tbl_name text,
    //   rootpage integer,
    //   sql text
    // );

    pub fn getTable(self: *Db, alloc: Allocator, table_name: []const u8) Error!SQLiteDbTable {
        // the first page contains the buffer (first 100 bytes), so we have a 0 offset to allocate the first page
        // TODO: buffer management
        readBuffer(self.buffer.ptr, 0, self.page_size);
        const new_slice = self.buffer.ptr[0..self.page_size]; // first page
        self.buffer = new_slice;
        const bt_header = SQLiteBtHeader.from(new_slice[sqlite_header_size..]);

        const cell_adr = bt_header.get_cell_addr(new_slice[sqlite_header_size..], 0);
        const cell_start = new_slice[cell_adr..];

        var record = SQLiteRecord.from(cell_start);

        // TODO: this could probably be refactored with comptime
        debug("table record: {}", .{record});
        while (true) {
            record.consume();
            record.consume();

            if (record.next()) |name_col| {
                if (name_col != SQLiteColumn.text) return Error.InvalidBinary;
                if (eql(u8, table_name, name_col.text)) {
                    if (record.next()) |index_col| {
                        const index_int = index_col.getInt();
                        if (index_int == null) return Error.InvalidBinary;
                        assert(index_int.? >= 0);
                        const page_index: u32 = @intCast(index_int.?);
                        debug("page_index: {d}", .{page_index});
                        if (record.next()) |sql_col| {
                            if (sql_col != SQLiteColumn.text) return Error.InvalidBinary;
                            const sql_str = try String.initAddSentinel(alloc, sql_col.text, 0);
                            return SQLiteDbTable{
                                .page = page_index,
                                .sql = sql_str,
                            };
                        }
                    } else {
                        return Error.InvalidBinary;
                    }
                } else {
                    record.consume();
                    record.consume();
                }
            } else {
                return Error.InvalidBinary;
            }
        }
        return Error.InvalidBinary;
    }
};

const ASTGen = struct {
    index: usize,
    gpa: Allocator,
    token_list: *TokenList,
    element_list: *ElementList,
    source: [:0]u8,
    db: Db,

    const State = enum {
        create,
        end,
        from,
        select_first,
        select_second,
        select_column,
        start,
        table,
        table_col_name,
        table_col_primary,
        table_col_type,
        table_name,
        table_next,
        where,
        where_comparison,
    };

    pub fn from(
        gpa: Allocator,
        token_list: *TokenList,
        element_list: *ElementList,
        source: [:0]u8,
        db: Db,
    ) Error!ASTGen {
        return ASTGen{
            .index = 0,
            .gpa = gpa,
            .token_list = token_list,
            .element_list = element_list,
            .source = source,
            .db = db,
        };
    }

    fn getTokenSource(buffer: [:0]const u8, min_token: MinimizedToken) []const u8 {
        if (min_token.tag.lexeme()) |lexeme| {
            return lexeme;
        }
        var tokenizer = Tokenizer.from(buffer, min_token.start);
        const token = tokenizer.next();
        debug("min token start, str: {d}, {s}. {s}", .{ token.location.start, buffer[token.location.start..token.location.end], buffer });
        return buffer[token.location.start..token.location.end];
    }

    fn getTokenEnd(buffer: [:0]const u8, min_token: MinimizedToken) u32 {
        var tokenizer = Tokenizer.from(buffer, min_token.start);
        const token = tokenizer.next();
        return token.location.end;
    }

    fn addElement(self: *ASTGen, elem: Element) Allocator.Error!u32 {
        const result = @as(u32, @intCast(self.element_list.len));
        try self.element_list.append(self.gpa, elem);
        return result;
    }

    fn getElement(self: *ASTGen, index: u32) Element {
        return self.element_list.get(index);
    }

    fn getElementData(self: *ASTGen, index: u32) Data {
        return self.element_list.items(.data)[index];
    }

    fn replaceDataAtIndex(self: *ASTGen, index: u32, data: Data) void {
        self.element_list.items(.data)[index] = .{
            .lhs = data.lhs,
            .rhs = data.rhs,
        };
    }

    fn replaceTagAtIndex(self: *ASTGen, index: u32, tag: ElementType) void {
        self.element_list.items(.tag)[index] = tag;
    }

    fn replaceNameAtIndex(self: *ASTGen, index: u32, name: String) void {
        self.element_list.items(.value)[index] = .{
            .str = name,
        };
    }

    fn addToken(self: *ASTGen, token: MinimizedToken) Allocator.Error!u32 {
        const result = @as(u32, @intCast(self.token_list.len));
        try self.token_list.append(self.gpa, token);
        return result;
    }

    fn buildCreateTable(self: *ASTGen, sqlite_table: SQLiteDbTable) Error!u32 {
        const PrimaryKeyState = enum {
            unfilled,
            current,
            filled,
        };

        // TODO: support tables derived from both the SQLite DB file and from CREATE statements.
        // Right now we only support from the DB file, which requires tokenizing the SQL from the DB file
        // We can also use the function call to push/pop index from stack instead of using an internal index
        var index = self.token_list.len;
        const sql_str = sqlite_table.sql;
        var tokenizer = Tokenizer.from(sql_str.strSentinel(), 0);
        try tokenizer.ingest(self.gpa, self.token_list);

        var state: State = .create;
        var name: ?String = null;
        var tag: ?ElementType = null;
        var primary_key: PrimaryKeyState = PrimaryKeyState.unfilled;
        var col_count: u32 = 0;
        var col_index: u32 = 0;
        var table_index: ?u32 = null;
        var primary_key_index: ?u32 = null;

        // TODO: errdefer dealloc elements of partially allocated table

        while (index < self.token_list.len) : (index += 1) {
            const token: MinimizedToken = self.token_list.get(index);
            switch (state) {
                .create => {
                    if (token.tag == .keyword_create) {
                        state = .table;
                    } else {
                        return Error.InvalidSyntax;
                    }
                },
                .table => {
                    if (token.tag == .keyword_table) {
                        state = .table_name;
                    } else {
                        return Error.InvalidSyntax;
                    }
                },
                .table_name => {
                    switch (token.tag) {
                        .word => {
                            const token_end = ASTGen.getTokenEnd(sql_str.strSentinel(), token);
                            const table_name = try sql_str.copySubstring(self.gpa, token.start, token_end);
                            table_index = try self.addElement(.{
                                .value = .{ .str = table_name },
                                .tag = ElementType.table,
                                .data = undefined,
                            });
                            // TODO: it doesn't make sense to store primary key always in the first column, because if its in a different order
                            // in the db then theres no way to map the column headers to the columns fields..
                            // so we need to indicate primary key index as a separate metadata info thing
                            // probably as a custom value in .rhs

                            primary_key_index = try self.addElement(.{
                                .value = undefined,
                                .tag = undefined,
                                .data = undefined,
                            });
                            col_index = primary_key_index.?;
                            self.replaceDataAtIndex(table_index.?, .{ .lhs = col_index, .rhs = sqlite_table.page });
                        },
                        .lparen => {
                            state = .table_col_name;
                        },
                        else => return Error.InvalidSyntax,
                    }
                },
                .table_col_name => {
                    switch (token.tag) {
                        .word => {
                            const token_end = ASTGen.getTokenEnd(sql_str.strSentinel(), token);
                            name = try sql_str.copySubstring(self.gpa, token.start, token_end);
                            col_count += 1;
                            state = .table_col_type;
                        },
                        else => return Error.InvalidSyntax,
                    }
                },
                .table_col_type => {
                    tag = switch (token.tag) {
                        .keyword_integer => ElementType.integer,
                        .keyword_text => ElementType.text,
                        else => return Error.InvalidSyntax,
                    };
                    state = .table_next;
                },
                .table_next => {
                    if (name == null or tag == null) {
                        return Error.InvalidSyntax;
                    }
                    switch (token.tag) {
                        .comma, .rparen => {
                            if (primary_key == PrimaryKeyState.current) {
                                primary_key = PrimaryKeyState.filled;
                                self.replaceNameAtIndex(primary_key_index.?, name.?);
                                debug("primary key tag: {}", .{tag.?});
                                self.replaceTagAtIndex(primary_key_index.?, tag.?);
                            } else {
                                const new_index = try self.addElement(.{
                                    .value = .{ .str = name.? },
                                    .tag = tag.?,
                                    .data = undefined,
                                });
                                self.replaceDataAtIndex(col_index, .{ .lhs = new_index, .rhs = 0 });
                                col_index = new_index;
                            }
                            if (token.tag == TokenType.comma) {
                                state = .table_col_name;
                            } else {
                                state = .end;
                            }
                        },
                        .keyword_primary => {
                            if (primary_key != PrimaryKeyState.unfilled) {
                                return Error.InvalidSyntax; // Primary key already filled
                            }
                            state = .table_col_primary;
                        },
                        else => return Error.InvalidSyntax,
                    }
                },
                .table_col_primary => {
                    switch (token.tag) {
                        .keyword_key => {
                            primary_key = PrimaryKeyState.current;
                            state = .table_next;
                        },
                        else => return Error.InvalidSyntax,
                    }
                },
                .end => {
                    self.replaceDataAtIndex(col_index, .{ .lhs = maxInt(u32), .rhs = 0 });
                    return table_index.?;
                },
                else => unreachable,
            }
        }

        return Error.InvalidSyntax;
    }

    fn buildSelectStatement(self: *ASTGen) Error!SelectStmt {
        var state: State = .select_first;
        var columns: u64 = 0;
        var table: ?TableStmt = null;
        var column_list_index: u32 = maxInt(u32);
        var processed_columns: bool = false;
        var where: ?Expr = null;
        while (self.index < self.token_list.len) : (self.index += 1) {
            const token = self.token_list.get(self.index);
            switch (state) {
                .select_first => {
                    switch (token.tag) {
                        .asterisk => {
                            // All columns
                            columns = max_64_bit;
                            processed_columns = true;
                        },
                        .keyword_from => {
                            state = .from;
                        },
                        .word => {
                            if (column_list_index == maxInt(u32)) {
                                column_list_index = self.index;
                            }
                        },
                        .comma => {},
                        else => {
                            break;
                        },
                    }
                },
                .select_second => {
                    switch (token.tag) {
                        .word => {
                            const col_name = ASTGen.getTokenSource(self.source, token);
                            if (table) |tbl| {
                                const is_col_index: ?u32 = tbl.getColumnIndex(self.element_list, col_name);
                                if (is_col_index) |col_index| {
                                    columns |= (@as(u64, 1) << @truncate(col_index));
                                } else {
                                    debug("Could not find column: {s}", .{col_name});
                                    break;
                                }
                            } else {
                                break;
                            }
                        },
                        .comma => {},
                        .keyword_from => {
                            processed_columns = true;
                            state = .from;
                        },
                        else => {
                            break;
                        },
                    }
                },
                .from => {
                    switch (token.tag) {
                        .word => {
                            if (table == null) {
                                const table_name = ASTGen.getTokenSource(self.source, token);
                                // TODO: return the table sql string if not allocated. If it is allocated, then it should return
                                // the table. I think the allocated tables should be a different struct
                                const sqlite_table = try self.db.getTable(self.gpa, table_name);
                                const table_data_index = try self.buildCreateTable(sqlite_table);
                                table = TableStmt.from(self.getElement(table_data_index));
                            }
                        },
                        .semicolon => {
                            if (processed_columns) {
                                state = .end;
                            } else {
                                state = .select_second;
                                self.index = column_list_index - 1;
                            }
                        },
                        else => {
                            break;
                        },
                    }
                },
                .where => {
                    where = try self.buildWhereClause(table.?);
                },
                .end => {
                    debug("AST built", .{});
                    break;
                },
                else => {
                    break;
                },
            }
        }

        if (table == null) {
            return Error.InvalidSyntax;
        }
        debug("table: {}", .{table.?});

        return SelectStmt{
            .columns = columns,
            .table = table.?,
            .where = where,
        };
    }

    pub fn buildWhereClause(self: *ASTGen, table: TableStmt) Error!?Expr {
        // var state: State = .where;
        var equality: ?TokenType = null;
        var col_index: ?u32 = null;
        var expr_index: ?u32 = null;
        var expr_first_index: ?u32 = null;
        while (self.index < self.token_list.len) : (self.index += 1) {
            const token = self.token_list.get(self.index);
            // TODO: add states
            switch (token.tag) {
                .word => {
                    const column_name = ASTGen.getTokenSource(self.source, token);
                    col_index = table.getColumnIndex(self.element_list, column_name);
                },
                .eq, .ne => {
                    equality = token.tag;
                },
                .double_quote_word => {
                    if (equality == null or col_index == null) {
                        return Error.InvalidSyntax;
                    }
                    const string_literal = ASTGen.getTokenSource(self.source, token);
                    const value = try String.init(self.gpa, string_literal[1..]);
                    const last_expr = expr_index;
                    expr_index = try self.addElement(.{
                        .value = .{ .str = value },
                        .tag = switch (equality.?) {
                            .eq => ElementType.compare_eq_str,
                            .ne => ElementType.compare_ne_str,
                            else => return Error.InvalidSyntax,
                        },
                        .data = .{ .lhs = col_index.?, .rhs = 0 },
                    });
                    if (last_expr) |expr| {
                        const data = self.getElementData(expr);
                        self.replaceDataAtIndex(expr, .{ .lhs = data.lhs, .rhs = expr_index.? });
                    } else {
                        expr_first_index = expr_index;
                    }
                },
                else => break,
            }
        }
        return null;
    }

    pub fn buildStatement(self: *ASTGen) Error!SelectStmt {
        var state: State = .start;
        // TODO: better handling, I think since there's a fixed buffer size this will iterate through 300 tokens even
        // if there isn't. Probably need an end token
        while (self.index < self.token_list.len) : (self.index += 1) {
            const token = self.token_list.get(self.index);
            switch (state) {
                .start => {
                    switch (token.tag) {
                        .keyword_select => {
                            state = .select_first;
                        },
                        else => {
                            break;
                        },
                    }
                },
                .select_first => {
                    const select = try self.buildSelectStatement();
                    debug("built statement: select({d}, {d})", .{ select.columns, select.table.page });
                    return select;
                },
                else => {
                    break;
                },
            }
        }
        return Error.InvalidSyntax;
    }
};

const TableMetadataReader = struct {
    element_list: *ElementList,
    index: u32,
    name: String,

    pub fn from(element_list: *ElementList, table_stmt: *const TableStmt) TableMetadataReader {
        return .{
            .element_list = element_list,
            .index = table_stmt.first_column,
            .name = table_stmt.name,
        };
    }

    pub fn next(self: *TableMetadataReader) ?Element {
        if (self.index % 100 == 0) {
            debug("next element: {d}, len: {d}", .{ self.index, self.element_list.len });
        }
        if (self.index >= self.element_list.len or self.index == maxInt(u32)) {
            return null;
        }
        const element = self.element_list.get(self.index);
        self.index = element.data.lhs;
        return element;
    }
};

const Stmt = union(enum) {
    select: SelectStmt,
};

const InstGen = struct {
    gpa: Allocator,
    element_list: *ElementList,
    inst_list: *InstList,
    statement: Stmt,
    db: Db,
    cursor_count: u8, // TODO: this count probably isn't necessary

    pub fn from(
        gpa: Allocator,
        element_list: *ElementList,
        inst_list: *InstList,
        db: Db,
        statement: Stmt,
    ) Error!InstGen {
        return InstGen{
            .gpa = gpa,
            .element_list = element_list,
            .inst_list = inst_list,
            .statement = statement,
            .db = db,
            .cursor_count = 0,
        };
    }

    // TODO: replace instruction list as struct with .Data and .Opcode. If > 2 32 bit values, then put it in extra_data arraylist

    fn addInst(self: *InstGen, inst: Inst) Allocator.Error!u32 {
        const result = @as(u32, @intCast(self.inst_list.len));
        try self.inst_list.append(self.gpa, inst);
        return result;
    }

    fn replaceP2AtIndex(self: *InstGen, index: u32, p2: u32) void {
        self.inst_list.items(.p2)[index] = p2;
    }

    fn markInst(self: *InstGen, opcode: Opcode) Error!u32 {
        return try self.addInst(.{ .opcode = opcode, .p1 = 0, .p2 = 0, .p3 = 0, .p4 = 0, .p5 = 0 });
    }

    fn instInit(self: *InstGen, index: u32, start_inst: u32) void {
        self.replaceP2AtIndex(index, start_inst);
    }

    fn openRead(self: *InstGen, index: u32, table_index: u32) void {
        self.replaceP2AtIndex(index, table_index);
        self.cursor_count += 1;
    }

    // The next use of the Rowid or Column or Next instruction for P1 will refer to the first entry in the database table or index.
    // If the table or index is empty, jump immediately to P2. If the table or index is not empty, fall through to the following instruction.
    // If P2 is zero, that is an assertion that the P1 table is never empty and hence the jump will never be taken.
    // This opcode leaves the cursor configured to move in forward order, from the beginning toward the end. In other words, the cursor is configured to use Next, not Prev.
    fn rewind(self: *InstGen, index: u32, end_inst: u32) void {
        self.replaceP2AtIndex(index, end_inst);
    }

    // Store in register P2 an integer which is the key of the table entry that P1 is currently point to.
    // P1 can be either an ordinary table or a virtual table. There used to be a separate OP_VRowid opcode for use with virtual tables,
    // but this one opcode now works for both table types.
    fn rowId(self: *InstGen, read_cursor: u32, store_reg: u32) Error!void {
        _ = try self.addInst(.{ .opcode = .row_id, .p1 = read_cursor, .p2 = store_reg, .p3 = 0, .p4 = 0, .p5 = 0 });
    }

    // Interpret the data that cursor P1 points to as a structure built using the MakeRecord instruction. Extract the P2-th column from this record.
    // If there are less than (P2+1) values in the record, extract a NULL.
    // The value extracted is stored in register P3.
    // If the record contains fewer than P2 fields, then extract a NULL. Or, if the P4 argument is a P4_MEM use the value of the P4 argument as the result.
    fn column(self: *InstGen, read_cursor: u32, store_reg: u32, col_num: u32) Error!void {
        _ = try self.addInst(.{ .opcode = .column, .p1 = read_cursor, .p2 = col_num, .p3 = store_reg, .p4 = 0, .p5 = 0 });
    }

    // The registers P1 through P1+P2-1 contain a single row of results. This opcode causes the sqlite3_step() call to terminate with an SQLITE_ROW return code
    // and it sets up the sqlite3_stmt structure to provide access to the r(P1)..r(P1+P2-1) values as the result row.
    fn resultRow(self: *InstGen, reg_index_start: u32, reg_index_end: u32) Error!void {
        _ = try self.addInst(.{ .opcode = .result_row, .p1 = reg_index_start, .p2 = reg_index_end, .p3 = 0, .p4 = 0, .p5 = 0 });
    }

    fn next(self: *InstGen, cursor: u32, success_jump: u32) Error!void {
        _ = try self.addInst(.{ .opcode = .next, .p1 = cursor, .p2 = success_jump, .p3 = 0, .p4 = 0, .p5 = 0 });
    }

    fn halt(self: *InstGen) Error!void {
        _ = try self.addInst(.{ .opcode = .halt, .p1 = 0, .p2 = 0, .p3 = 0, .p4 = 0, .p5 = 0 });
    }

    // Begin a transaction on database P1 if a transaction is not already active. If P2 is non-zero, then a write-transaction is started,
    // or if a read-transaction is already active, it is upgraded to a write-transaction. If P2 is zero, then a read-transaction is started.
    // If P2 is 2 or more then an exclusive transaction is started.
    // P1 is the index of the database file on which the transaction is started. Index 0 is the main database file and index 1 is the file
    // used for temporary tables. Indices of 2 or more are used for attached databases.
    // If P5!=0 then this opcode also checks the schema cookie against P3 and the schema generation counter against P4.
    // The cookie changes its value whenever the database schema changes. This operation is used to detect when that the cookie has changed
    // and that the current process needs to reread the schema. If the schema cookie in P3 differs from the schema cookie in the database header
    // or if the schema generation counter in P4 differs from the current generation counter, then an SQLITE_SCHEMA error is raised and
    // execution halts. The sqlite3_step() wrapper function might then reprepare the statement and rerun it from the beginning.
    fn transaction(self: *InstGen, database_id: u32, write: bool) Error!void {
        const write_int: u32 = if (write) 1 else 0;
        _ = try self.addInst(.{ .opcode = .transaction, .p1 = database_id, .p2 = write_int, .p3 = 0, .p4 = 0, .p5 = 0 });
    }

    fn goto(self: *InstGen, inst_jump: u32) Error!void {
        _ = try self.addInst(.{ .opcode = .goto, .p1 = 0, .p2 = inst_jump, .p3 = 0, .p4 = 0, .p5 = 0 });
    }

    pub fn buildInstructions(self: *InstGen) Error!void {
        switch (self.statement) {
            Stmt.select => {
                const select = self.statement.select;
                const page_index: u32 = select.table.page - 1;
                debug("page_index: {d}", .{page_index});

                const cursor = 0;

                const init_index = try self.markInst(.init);
                const open_read_index = try self.markInst(.open_read);
                const rewind_index = try self.markInst(.rewind);
                const rewind_start = self.inst_list.len;

                var col_count: u32 = 0;
                var output_count: u32 = 0;
                var reader = TableMetadataReader.from(self.element_list, &select.table);
                while (reader.next()) |col| {
                    // TODO: support more than 64 columns
                    if (select.columns & (@as(u64, 0x1) << @truncate(col_count)) > 0) {
                        if (col_count == 0 and col.tag == .integer) {
                            // rowId reads for a integer primary key row. If this isn't explicitly noted as a primary key,
                            // then column instruction is used instead.
                            try self.rowId(cursor, output_count + 1);
                        } else {
                            try self.column(cursor, output_count + 1, col_count);
                        }
                        output_count += 1;
                    }
                    col_count += 1;
                }
                debug("columns: {b}", .{select.columns});

                debug("output count: {d}", .{output_count});
                try self.resultRow(1, output_count + 1);
                try self.next(cursor, rewind_start);
                try self.halt();
                const halt_index = self.inst_list.len - 1;
                // TODO: support multiples databases, writing to tables
                try self.transaction(0, false);
                const transaction_index = self.inst_list.len - 1;
                try self.goto(open_read_index);
                self.instInit(init_index, transaction_index);
                self.openRead(open_read_index, page_index);
                self.rewind(rewind_index, halt_index);
                debug("instructions written", .{});
            },
        }
    }
};

const Vm = struct {
    gpa: Allocator,
    db: Db,
    inst_list: InstList.Slice,
    reg_list: ArrayListUnmanaged(Register),
    pc: u32,

    const Cursor = struct {
        addr: u16,
        index: u32,
    };

    pub fn from(gpa: Allocator, db: Db, inst_list: InstList.Slice) Vm {
        return .{
            .gpa = gpa,
            .db = db,
            .inst_list = inst_list,
            .reg_list = .{},
            .pc = 0,
        };
    }

    fn reg(self: *Vm, index: u32, register: Register) Error!void {
        debug("reg index: {d}, len: {d}", .{ index, self.reg_list.items.len });
        // registers start at 1, not 0
        if (index - 1 == self.reg_list.items.len) {
            try self.reg_list.append(self.gpa, register);
        } else {
            self.reg_list.items[index - 1] = register;
        }
    }

    pub fn exec(self: *Vm) Error!void {
        var instruction = self.inst_list.get(self.pc);
        // TODO: multiple cursors
        // TODO: clean up these variables
        var buffer: ?[]u8 = null;
        var header: ?*SQLiteBtHeader = null;
        var record: ?SQLiteRecord = null;
        var col_count: u32 = 0;
        var cell_size: u32 = 0;
        var cell_count: u32 = 0;
        var col_value: ?SQLiteColumn = null;

        while (self.pc < self.inst_list.len and instruction.opcode != .halt) {
            instruction = self.inst_list.get(self.pc);
            switch (instruction.opcode) {
                .init => {
                    self.pc = instruction.p2;
                },
                .open_read => {
                    const page_index = instruction.p2;
                    buffer = self.db.readPage(page_index);
                    debug("buffer created", .{});
                    header = SQLiteBtHeader.from(buffer.?);
                    // TODO: refactor this mess
                    cell_size = header.?.get_cell_count();
                    debug("cell count: {d}", .{cell_size});
                    const addr = header.?.get_cell_addr(buffer.?, cell_count);
                    debug("cell address: {x}", .{addr});
                    record = SQLiteRecord.from(buffer.?[addr..]);
                    self.pc += 1;
                },
                .rewind => {
                    // TODO: escape when table is empty
                    assert(record != null);
                    col_value = record.?.next();
                    if (col_value == null) {
                        break;
                    }
                    col_count += 1;
                    self.pc += 1;
                },
                .row_id => {
                    assert(record != null);
                    assert(col_value != null);
                    const value = col_value.?;
                    debug("row_id SQLiteColumn: {s}", .{@tagName(value)});
                    try self.reg(instruction.p2, Register{ .int = @intCast(record.?.row_id) });
                    col_value = record.?.next();
                    col_count += 1;
                    self.pc += 1;
                },
                .column => {
                    assert(record != null);
                    const col = instruction.p2;
                    if (col_count < col) {
                        while (col_count < col) : (col_count += 1) {
                            record.?.consume();
                        }
                        col_value = record.?.next();
                        col_count += 1;
                    }
                    assert(col_value != null);
                    try self.reg(instruction.p3, Register.from_column(col_value.?));
                    col_value = record.?.next();
                    debug("col_value: {?}", .{col_value});
                    col_count += 1;
                    self.pc += 1;
                },
                .result_row => {
                    const start_reg = instruction.p1;
                    const end_reg = instruction.p2;

                    // TODO: callback method to handle these regs or smth. Right now we will simply log them to console
                    var i = start_reg;
                    var write_buf: [256]u8 = undefined;
                    var write_count: u8 = 0;
                    while (i < end_reg) : (i += 1) {
                        const written = self.reg_list.items[i - 1].to_str(@constCast(write_buf[write_count..])) catch write_buf[write_count..];
                        const written_len: u8 = @intCast(written.len);
                        debug("written len: {d}", .{written_len});
                        write_count += written_len;
                        if (i != end_reg - 1) {
                            write_buf[write_count] = '|';
                            write_count += 1;
                        }
                    }
                    print(write_buf[0..write_count].ptr, write_buf[0..write_count].len);
                    self.pc += 1;
                },
                .next => {
                    debug("col_value: {?}", .{col_value});
                    if (cell_count >= cell_size - 1) {
                        self.pc += 1;
                    } else {
                        cell_count += 1;

                        const addr = header.?.get_cell_addr(buffer.?, cell_count);
                        debug("cell address: {x}", .{addr});
                        record = SQLiteRecord.from(buffer.?[addr..]);
                        col_value = record.?.next();

                        const inst_addr = instruction.p2;
                        self.pc = inst_addr;
                    }
                },
                .halt => break,
                .transaction => {
                    // TODO: support transactions, attached databases, writing
                    self.pc += 1;
                },
                .goto => {
                    self.pc = instruction.p2;
                },
                // else => debug("instruction not implemented: {}", .{instruction.opcode}),
            }
        }
    }
};

const MinimizedToken = struct { tag: TokenType, start: u32 };
const String = struct {
    index: u32,
    len: u32,

    const Self = @This();

    pub fn str(self: *const Self) []const u8 {
        return string_bytes.items[self.index .. self.index + self.len];
    }

    pub fn strSentinel(self: *const Self) [:0]const u8 {
        assert(hasSentinel(self, 0));
        return string_bytes.items[self.index .. self.index + self.len - 1 :0];
    }

    pub fn hasSentinel(self: *const Self, sentinel: u8) bool {
        return string_bytes.items[self.index + self.len - 1] == sentinel;
    }

    pub fn initAssumeCapacity(chars: []const u8) Self {
        const len: u32 = @intCast(string_bytes.items.len);
        string_bytes.appendSliceAssumeCapacity(chars);
        return Self{ .index = len, .len = chars.len };
    }

    pub fn ensureExtraCapacity(alloc: Allocator, additional_count: u32) !void {
        try string_bytes.ensureUnusedCapacity(alloc, additional_count);
    }

    pub fn init(alloc: Allocator, chars: []const u8) !Self {
        const len: u32 = @intCast(string_bytes.items.len);
        try string_bytes.appendSlice(alloc, chars);
        return Self{ .index = len, .len = chars.len };
    }

    pub fn copySubstring(self: *const Self, alloc: Allocator, start_index: u32, end_index: u32) !Self {
        try String.ensureExtraCapacity(alloc, end_index - start_index);
        return String.initAssumeCapacity(self.str()[start_index..end_index]);
    }

    pub fn initAddSentinel(alloc: Allocator, chars: []const u8, comptime sentinel: u8) !Self {
        const len: u32 = @intCast(string_bytes.items.len);
        try string_bytes.appendSlice(alloc, chars);
        try string_bytes.append(alloc, sentinel);
        return Self{ .index = len, .len = chars.len + 1 };
    }
};

var string_bytes: ArrayListUnmanaged(u8) = .{};
const TokenList = MultiArrayList(MinimizedToken);
const ElementList = MultiArrayList(Element);
const InstList = MultiArrayList(Inst);

fn parseStatement(str: [:0]u8, file_buffer: []u8) Error!void {
    var tokenizer = Tokenizer.from(str, 0);
    var fixed_alloc = heap.FixedBufferAllocator.init(&memory_buf);

    var tokens = TokenList{};
    defer tokens.deinit(fixed_alloc.allocator());

    var data = ElementList{};
    defer data.deinit(fixed_alloc.allocator());

    var insts = InstList{};
    defer insts.deinit(fixed_alloc.allocator());

    try tokenizer.ingest(fixed_alloc.allocator(), &tokens);

    const db = try Db.from(file_buffer);

    // ASTGen can allocate more tokens, so we pass the struct instead of the underlying buffer
    var ast = try ASTGen.from(fixed_alloc.allocator(), &tokens, &data, str, db);
    const statement = try ast.buildStatement();
    debug("statement built!", .{});

    var inst_gen = try InstGen.from(fixed_alloc.allocator(), &data, &insts, db, Stmt{ .select = statement });
    debug("inst generated!", .{});

    // TODO: ast built, now translate into instructions for VM.
    try inst_gen.buildInstructions();

    var vm = Vm.from(fixed_alloc.allocator(), db, inst_gen.inst_list.slice());
    try vm.exec();
}

export fn runStatementWithFile(ptr: ?*u8, size: usize) void {
    if (ptr == null) {
        debug("uh oh no pointer", .{});
        return;
    }
    const buffer: [*]u8 = @as([*]u8, @ptrCast(ptr));
    const slice = buffer[0..size];

    parseStatement(&query_buf, slice) catch |err| {
        switch (err) {
            Error.InvalidBinary => debug("uh oh stinky binary file", .{}),
            Error.InvalidSyntax => debug("uh oh stinky SQL syntax", .{}),
            Error.OutOfMemory => debug("uh oh allocator ran out of memory", .{}),
        }
        return;
    };
}

export fn getStatementAddr() [*]u8 {
    return &query_buf;
}

// export fn free(ptr: *u8) void {
//     const page_allocator = heap.page_allocator;
//     page_allocator.free(@as([*]u8, @ptrCast(ptr)));
// }
