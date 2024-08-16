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
        block = @as(u16, self.metadata[2]) << 8;
        block |= self.metadata[1];
        return block;
    }

    pub fn get_cell_count(self: *SQLiteBtHeader) u16 {
        var block: u16 = 0;
        block = @as(u16, self.metadata[4]) << 8;
        block |= self.metadata[3];
        return block;
    }

    pub fn get_cell_offset(self: *SQLiteBtHeader) u16 {
        var block: u16 = 0;
        block = @as(u16, self.metadata[6]) << 8;
        block |= self.metadata[5];
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

const err_string = "Error!";
const select_str = "SELECT * FROM example;";

const one_kb = 1024;
const query_buffer_size = 512;
const memory_buffery_size = 32 * one_kb;
var query_buf: [query_buffer_size]u8 = undefined;
var memory_buf: [memory_buffery_size]u8 = undefined;
var vm: Vm = .{
    .pc = 0,
    .insts = undefined,
    .registers = undefined,
    .stmt = null,
};

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
            .lparen => "(",
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
        semicolon,
        double_quote_word,
        int,
        identifier,
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
            print(self.buffer[token.location.start..token.location.end].ptr, token.location.end - token.location.start);
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
                    ' ', '\n' => {
                        token.location.start = self.index + 1;
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
    // TODO: Expr uses Element struct, value is val, tag is type of comparison, and data lhs rhs are the right and left linked
    // list expressions
};

const SelectStmt = struct {
    columns: u64, // Each bit represents one column in the table
    table: TableStmt,
    where: *Expr,
};

const ElementType = enum {
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
    p4: u64,
    p5: u16,
};

const Opcode = enum(u8) {
    init,
    open_read,
    rewind,
    rowid,
    column,
    result_row,
    next,
    halt,
    transaction,
    goto,
};

const Register = struct {
    memory: union {
        int: i64,
        float: f64,
    },
    str: *u8,
    len: u32,
};

const Vm = struct {
    pc: u32,
    registers: [100]Register,
    insts: [100]Inst,
    stmt: ?SelectStmt,
}; // 100 instructions, 100 stack, 100 instructions

const SQLiteDbTable = struct {
    page: u32,
    sql: String,
};

const SQLiteColumnValue = struct {
    type: SQLiteColumnType,
    value: union {
        int: i64,
        float: f64,
        slice: []u8,
    },

    pub fn from(col_type: SQLiteColumnType, val: []u8) SQLiteColumnValue {
        switch (col_type) {
            .empty, .value_0, .value_1 => {
                return .{ .type = col_type, .value = .{ .int = 0 } };
            },
            .i8 => {
                return .{ .type = col_type, .value = .{ .int = @intCast(val[0]) } };
            },
            .i16 => {
                return .{
                    .type = col_type,
                    .value = .{ .int = @byteSwap(valFromSlice(i16, val)) },
                };
            },
            .i24 => {
                return .{
                    .type = col_type,
                    .value = .{ .int = @byteSwap(valFromSlice(i24, val)) },
                };
            },
            .i32 => {
                return .{
                    .type = col_type,
                    .value = .{ .int = @byteSwap(valFromSlice(i32, val)) },
                };
            },
            .i48 => {
                return .{
                    .type = col_type,
                    .value = .{ .int = @byteSwap(valFromSlice(i48, val)) },
                };
            },
            .i64 => {
                return .{
                    .type = col_type,
                    .value = .{ .int = @byteSwap(valFromSlice(i64, val)) },
                };
            },
            .f64 => {
                const result = valFromSlice(u64, val);
                return .{
                    .type = col_type,
                    .value = .{ .float = @floatFromInt(@byteSwap(result)) },
                };
            },
            .blob, .text => {
                return .{
                    .type = col_type,
                    .value = .{ .slice = val },
                };
            },
            .invalid => {
                return .{ .type = .invalid, .value = .{ .int = 0 } };
            },
        }
    }
};

const SQLiteRecord = struct {
    buffer: []u8,
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
        var row_id: u64 = 0; // TODO: use this?

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

    pub fn next(self: *SQLiteRecord) ?SQLiteColumnValue {
        if (self.cursor >= self.size) return null;
        if (self.header_cursor >= self.header_size) {
            self.header_cursor = 0;
        }
        var header_val: u64 = 0;
        self.header_cursor += get_varint(self.buffer.ptr + self.header_cursor, &header_val);

        const size: u32 = @truncate(SQLiteColumnType.size(header_val));

        const col_type = SQLiteColumnType.from(header_val);
        debug("next() size: {d} col_type: {}", .{ size, col_type });

        if (size == 0) {
            return SQLiteColumnValue.from(col_type, self.buffer);
        }

        const result = SQLiteColumnValue.from(
            col_type,
            self.buffer[self.cursor .. self.cursor + size],
        );

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

        self.cursor += @truncate(SQLiteColumnType.size(header_val));
    }
};

const SQLiteColumnType = enum {
    empty,
    i8,
    i16,
    i24,
    i32,
    i48,
    i64,
    f64,
    value_0,
    value_1,
    invalid,
    blob,
    text,

    pub fn from(val: u64) SQLiteColumnType {
        switch (val) {
            0 => return .empty,
            1 => return .i8,
            2 => return .i16,
            3 => return .i24,
            4 => return .i32,
            5 => return .i48,
            6 => return .i64,
            7 => return .f64,
            8 => return .value_0,
            9 => return .value_1,
            10, 11 => return .invalid,
            else => {
                if (val % 2 == 0) {
                    return .blob;
                }
                return .text;
            },
        }
    }

    pub fn isInt(self: SQLiteColumnType) bool {
        switch (self) {
            .i8, .i16, .i24, .i32, .i48, .i64 => return true,
            else => return false,
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
    cursor: usize,
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
        debug("page start {d}", .{page_start});
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
                if (name_col.type != SQLiteColumnType.text) return Error.InvalidBinary;
                if (eql(u8, table_name, name_col.value.slice)) {
                    if (record.next()) |index_col| {
                        if (!index_col.type.isInt()) return Error.InvalidBinary;
                        assert(index_col.value.int >= 0);
                        const page_index: u32 = @intCast(index_col.value.int);
                        debug("page_index: {d}", .{page_index});
                        if (record.next()) |sql_col| {
                            if (sql_col.type != SQLiteColumnType.text) return Error.InvalidBinary;
                            const sql_str = try String.initAddSentinel(alloc, sql_col.value.slice, 0);
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
    vm: Vm,
    db: Db,

    const State = enum {
        create,
        end,
        from,
        select,
        select_column,
        start,
        table,
        table_col_name,
        table_col_primary,
        table_col_type,
        table_name,
        table_next,
    };

    pub fn from(
        gpa: Allocator,
        token_list: *TokenList,
        element_list: *ElementList,
        source: [:0]u8,
        file_buffer: []u8,
    ) Error!ASTGen {
        const db = try Db.from(file_buffer);
        return ASTGen{
            .index = 0,
            .gpa = gpa,
            .token_list = token_list,
            .element_list = element_list,
            .source = source,
            .vm = vm, // TODO: more than one VM?
            .db = db,
        };
    }

    fn getTokenSource(buffer: [:0]const u8, min_token: MinimizedToken) []const u8 {
        if (min_token.tag.lexeme()) |lexeme| {
            return lexeme;
        }
        var tokenizer = Tokenizer.from(buffer, min_token.start);
        const token = tokenizer.next();
        return buffer[token.location.start..token.location.end];
    }

    fn addElement(self: *ASTGen, elem: Element) Allocator.Error!u32 {
        const result = @as(u32, @intCast(self.element_list.len));
        try self.element_list.append(self.gpa, elem);
        return result;
    }

    fn getElement(self: *ASTGen, index: u32) Element {
        return self.element_list.get(index);
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
        const sql_str = sqlite_table.sql.strSentinel();
        var tokenizer = Tokenizer.from(sql_str, 0);
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
                            const table_name = ASTGen.getTokenSource(sql_str, token);
                            table_index = try self.addElement(.{
                                .value = .{ .str = try String.init(self.gpa, table_name) },
                                .tag = ElementType.table,
                                .data = undefined,
                            });
                            primary_key_index = try self.addElement(.{
                                .value = undefined,
                                .tag = undefined,
                                .data = undefined,
                            });
                            self.replaceDataAtIndex(table_index.?, .{ .lhs = col_index, .rhs = sqlite_table.page });
                            col_index = primary_key_index.?;
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
                            name = try String.init(self.gpa, ASTGen.getTokenSource(sql_str, token));
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
                    self.replaceDataAtIndex(col_index, .{ .lhs = 0, .rhs = 0 });
                    return table_index.?;
                },
                else => unreachable,
            }
        }

        return Error.InvalidSyntax;
    }

    fn buildSelectStatement(self: *ASTGen) Error!SelectStmt {
        var state: State = .select;
        var columns: u64 = 0;
        var table: ?TableStmt = null;
        while (self.index < self.token_list.len) : (self.index += 1) {
            const token = self.token_list.get(self.index);
            switch (state) {
                .select => {
                    switch (token.tag) {
                        .asterisk => {
                            // All columns
                            columns = max_64_bit;
                        },
                        .keyword_from => {
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
                            const table_name = ASTGen.getTokenSource(self.source, token);
                            // TODO: return the table sql string if not allocated. If it is allocated, then it should return
                            // the table. I think the allocated tables should be a different struct
                            const sqlite_table = try self.db.getTable(self.gpa, table_name);
                            const table_data_index = try self.buildCreateTable(sqlite_table);
                            table = TableStmt.from(self.getElement(table_data_index));
                        },
                        .semicolon => {
                            state = .end;
                        },
                        else => {
                            break;
                        },
                    }
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
            .where = undefined,
        };
    }

    pub fn buildStatement(self: *ASTGen) Error!void {
        var state: State = .start;
        // TODO: better handling, I think since there's a fixed buffer size this will iterate through 300 tokens even
        // if there isn't. Probably need an end token
        while (self.index < self.token_list.len) : (self.index += 1) {
            const token = self.token_list.get(self.index);
            switch (state) {
                .start => {
                    switch (token.tag) {
                        .keyword_select => {
                            state = .select;
                        },
                        else => {
                            break;
                        },
                    }
                },
                .select => {
                    self.vm.stmt = try self.buildSelectStatement();
                    break;
                },
                else => {
                    break;
                },
            }
        }
        debug("built statement: select({d}, {d})", .{ self.vm.stmt.?.columns, self.vm.stmt.?.table.page });
    }

    pub fn buildInstructions(self: *ASTGen) void {
        if (self.vm.stmt) |stmt| {
            // TODO: handle statement
            const index: u32 = stmt.table.page - 1;
            debug("index: {d}", .{index});

            const buffer = self.db.readPage(index);
            debug("buffer created", .{});
            const header = SQLiteBtHeader.from(buffer);
            const addr = header.get_cell_addr(buffer, 0);

            var record = SQLiteRecord.from(buffer[addr..]);
            while (record.next()) |first| {
                debug("in table: {}", .{first.type});
                if (first.type == SQLiteColumnType.text) {
                    debug("text: {s}", .{first.value.slice});
                }
            }
        } else {
            debug("no select statement to build!", .{});
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
        debug("index: {d}, str len: {d}, bytes len: {d}", .{ self.index, self.len, string_bytes.items.len });
        return string_bytes.items[self.index .. self.index + self.len - 1 :0];
    }

    pub fn hasSentinel(self: *const Self, sentinel: u8) bool {
        return string_bytes.items[self.index + self.len - 1] == sentinel;
    }

    pub fn init(alloc: Allocator, chars: []const u8) !Self {
        const len: u32 = @intCast(string_bytes.items.len);
        try string_bytes.appendSlice(alloc, chars);
        return Self{ .index = len, .len = chars.len };
    }

    pub fn initAddSentinel(alloc: Allocator, chars: []const u8, comptime sentinel: u8) !Self {
        const len: u32 = @intCast(string_bytes.items.len);
        try string_bytes.appendSlice(alloc, chars);
        try string_bytes.append(alloc, sentinel);
        return Self{ .index = len, .len = chars.len + 1 };
    }
};

const TokenList = MultiArrayList(MinimizedToken);
var string_bytes: ArrayListUnmanaged(u8) = .{};
const ElementList = MultiArrayList(Element);

fn parseStatement(str: [:0]u8, file_buffer: []u8) Error!void {
    var tokenizer = Tokenizer.from(str, 0);
    var fixed_alloc = heap.FixedBufferAllocator.init(&memory_buf);

    var tokens = TokenList{};
    defer tokens.deinit(fixed_alloc.allocator());

    var data = ElementList{};
    defer data.deinit(fixed_alloc.allocator());

    try tokenizer.ingest(fixed_alloc.allocator(), &tokens);

    // ASTGen can allocate more tokens, so we pass the struct instead of the underlying buffer
    var ast = try ASTGen.from(fixed_alloc.allocator(), &tokens, &data, str, file_buffer);
    try ast.buildStatement();

    // TODO: ast built, now translate into instructions for VM.
    ast.buildInstructions();
}

export fn parse_buffer(ptr: ?*u8, size: usize) void {
    if (ptr == null) {
        print(err_string, err_string.len);
        return;
    }
    const buffer: [*]u8 = @as([*]u8, @ptrCast(ptr));
    const slice = buffer[0..size];

    parseStatement(@constCast(select_str), slice) catch |err| {
        switch (err) {
            Error.InvalidBinary => debug("uh oh stinky binary file", .{}),
            Error.InvalidSyntax => debug("uh oh stinky SQL syntax", .{}),
            Error.OutOfMemory => debug("uh oh allocator ran out of memory", .{}),
        }
        return;
    };

    // TODO: remove code below
    if (true) {
        return;
    }
    if (slice.len < @sizeOf(SQLiteDbHeader)) {
        print(err_string, err_string.len);
        return;
    }
    // make sure not to overwrite the first 100 bytes in the buffer.. otherwise header goes away :(
    const header_size = @sizeOf(SQLiteDbHeader);
    const bt_header_size = @sizeOf(SQLiteBtHeader);
    debug("bt_header_size: {d}", .{bt_header_size});
    const header: *SQLiteDbHeader = @alignCast(@ptrCast(slice[0..header_size]));
    print(&(header.header_string), header.header_string.len);
    const page_size = header.get_page_size();
    debug("page_size: {d}", .{page_size});
    readBuffer(buffer, 0, page_size); // the first page contains the buffer (first 100 bytes), so we have a 0 offset to allocate the first page
    const new_slice = buffer[0..page_size]; // first page
    const bt_header: *SQLiteBtHeader = @alignCast(@ptrCast(new_slice[header_size .. header_size + bt_header_size]));
    const cell_count = bt_header.get_cell_count();
    debug("cell_count: {d}", .{cell_count});
    debug("page_type: {d}", .{bt_header.get_page_type()});
    debug("free_block: {d}", .{bt_header.get_first_freeblock()});
    debug("sqlite version num: {d}", .{header.get_version()});

    // now read the first cell pointer (2 byte offset)
    const cell_ptr: *u16 = @alignCast(@ptrCast(new_slice[header_size + bt_header_size - 4 .. header_size + bt_header_size - 2]));
    const cell_adr: u16 = @byteSwap(cell_ptr.*);
    debug("first cell: {d}", .{cell_adr});

    // now read the first cell
    const cell_start = new_slice[cell_adr..];
    var cell_header_size: u64 = undefined;
    var size_so_far: u32 = 0;
    size_so_far += get_varint(cell_start.ptr, &cell_header_size);
    debug("cell header size: {d}", .{cell_header_size});
}

// export fn free(ptr: *u8) void {
//     const page_allocator = std.heap.page_allocator;
//     page_allocator.free(@as([*]u8, @ptrCast(ptr)));
// }
