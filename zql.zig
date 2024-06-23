const heap = @import("std").heap;
const assert = @import("std").debug.assert;
const fmt = @import("std").fmt;
const panic = @import("std").debug.panic;
const StaticStringMap = @import("std").StaticStringMapWithEql;
const eqlLenIgnoreCase = @import("std").static_string_map.eqlAsciiIgnoreCase;

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
        assert(self.get_page_type() != 0x0D and self.get_page_type() != 0x0A, "Leaf pages don't have right child pages");
        return @byteSwap(self.right_child_page);
    }
};

// Bit masks fo get_varint
const bits_7 = 0x7f;
const slot_2_0 = (0x7f << 14) | 0x7f;
const slot_4_2_0 = (0x7f << 28) | slot_2_0;

const err_string = "Error!";
const select_str = "SELECT * FROM example;";

var query_buf: [300]u8 = undefined;
var token_buf: [200]Token = undefined;
var vm: Vm = undefined;

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
    debug("uh oh I panic -><- uwu ", .{});
    panic("uh oh I panic -><- uwu ", .{});
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
    keyword_select,
    keyword_from,
    keyword_where,
    keyword_and,
    keyword_or,
    invalid,

    pub fn lexeme(token_type: TokenType) ?[]const u8 {
        return switch (token_type) {
            .asterisk => "*",
            .semicolon => ";",
            .keyword_and => "AND",
            .keyword_from => "FROM",
            .keyword_or => "OR",
            .keyword_select => "SELECT",
            .keyword_where => "WHERE",
            else => null,
        };
    }
};

const TokenValue = union {
    int: i64,
    float: f64,
    idx: struct {
        start: u32,
        len: u32,
    },
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
        .{ "from", TokenType.keyword_from },
        .{ "or", TokenType.keyword_or },
        .{ "select", TokenType.keyword_select },
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

    pub fn from(buffer: [:0]const u8) Tokenizer {
        return Tokenizer{
            .buffer = buffer,
            .index = 0,
        };
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
                        state = .semicolon;
                    },
                    '*' => {
                        state = .asterisk;
                    },
                    else => {
                        token.type = .invalid;
                        token.location.end = self.index;
                        self.index += 1;
                        return token;
                    },
                },
                .asterisk => {
                    token.type = TokenType.asterisk;
                    break;
                },
                .semicolon => {
                    token.type = TokenType.semicolon;
                    break;
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
    left: *Expr,
    right: *Expr,
    op: TokenType,
    value: TokenValue,
};

const SelectStmt = struct {
    columns: u64,
    table: u32,
    where: *Expr,
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
    stmt: SelectStmt,
}; // 100 instructions, 100 stack, 100 instructions

const ASTBuilder = struct {
    index: usize,
    buffer: [*]Token,
    vm: Vm,

    const State = enum {
        start,
        end,
        select,
        select_column,
        from,
    };

    pub fn from(buffer: [*]Token) void {
        return ASTBuilder{
            .index = 0,
            .buffer = buffer,
        };
    }

    fn build_select_statement(self: *ASTBuilder) SelectStmt {
        var state: State = .select;
        while (self.index < self.buffer.len) : (self.index += 1) {
            const token = self.buffer[self.index];
            switch (state) {
                .select => {
                    switch (token) {
                        .asterisk => {
                            // All columns
                        },
                    }
                },
            }
        }
    }

    pub fn build_statement(self: *ASTBuilder) void {
        var state: State = .start;
        while (self.index < self.buffer.len) : (self.index += 1) {
            const token = self.buffer[self.index];
            switch (state) {
                .start => {
                    switch (token) {
                        .keyword_select => {
                            state = .select;
                        },
                        else => {
                            break;
                        },
                    }
                },
                .select => {
                    build_select_statement();
                },
                else => {},
            }
        }
    }
};

fn parse_statement(str: [:0]u8) void {
    var tokenizer = Tokenizer.from(str);
    var token_count: u32 = 0;
    while (token_count < token_buf.len) : (token_count += 1) {
        var token = tokenizer.next();
        token_buf[token_count] = token;
        if (token.type == TokenType.eof) {
            break;
        }
        // debugging
        tokenizer.dump(&token);
    }
}

export fn parse_buffer(ptr: ?*u8, size: usize) void {
    parse_statement(@constCast(select_str));
    if (ptr == null) {
        print(err_string, err_string.len);
        return;
    }
    const buffer: [*]u8 = @as([*]u8, @ptrCast(ptr));
    const slice = buffer[0..size];
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
