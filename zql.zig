const std = @import("std");
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const assert = std.debug.assert;
const eql = std.mem.eql;
const eqlLenIgnoreCase = std.static_string_map.eqlAsciiIgnoreCase;
const FixedBufferStream = std.io.FixedBufferStream;
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
const maxInt = std.math.maxInt;
const meta = std.meta;
const MultiArrayList = std.MultiArrayList;
const panic = std.debug.panic;
const StaticStringMap = std.StaticStringMapWithEql;

// (arrayPointer: i32, length: i32)
extern fn print(ptr: [*]const u8, len: usize) void;

extern fn readBuffer(ptr: [*]const u8, offset: usize, len: usize) void;

extern fn renderRow(ptr: [*]const u8, len: usize) void;

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

// TODO: use meta.activeTag to get the active tag for tagged enum for comparing two tagged enums, such as Register

const InternPool = struct {
    items: MultiArrayList(Item),
    extra: ArrayListUnmanaged(u32),
    string_bytes: ArrayListUnmanaged(u8),

    const Tag = enum(u8) {
        table,
        column,
        instruction,
        register,
        condition,
    };

    const Item = struct {
        tag: Tag,
        data: Data,
    };

    const Index = enum(u32) {
        _,
        pub fn toOptional(dep: InternPool.Index) Optional {
            return @enumFromInt(@intFromEnum(dep));
        }
        pub const Optional = enum(u32) {
            none = maxInt(u32),
            _,
            pub fn unwrap(opt: Optional) ?InternPool.index {
                return switch (opt) {
                    .none => return null,
                    _ => @enumFromInt(@intFromEnum(opt)),
                };
            }
        };
    };

    /// An index into `strings` which might be `none`.
    pub const OptionalString = enum(u32) {
        /// This is distinct from `none` - it is a valid index that represents empty string.
        empty = 0,
        none = std.math.maxInt(u32),
        _,

        pub fn unwrap(string: OptionalString) ?String {
            return if (string != .none) @enumFromInt(@intFromEnum(string)) else null;
        }

        pub fn toSlice(string: OptionalString, len: u64, ip: *const InternPool) ?[]const u8 {
            return (string.unwrap() orelse return null).toSlice(len, ip);
        }
    };

    const NullTerminatedString = enum(u32) {
        /// An empty string.
        empty = 0,
        _,

        const Self = @This();

        fn unwrap(self: *const Self) u32 {
            return @intFromEnum(self);
        }

        pub fn toString(self: NullTerminatedString) String {
            return @enumFromInt(@intFromEnum(self));
        }

        pub fn slice(self: *const Self) [:0]const u8 {
            const string = self.toString();
            const index = string.unwrap();
            const full_slice = string.sliceToEnd();
            return string_bytes.items[index .. index + std.mem.indexOfScalar(u8, full_slice, 0).? :0];
        }
    };

    const String = enum(u32) {
        /// An empty string.
        empty = 0,
        _,

        const Self = @This();

        fn unwrap(self: *const Self) u32 {
            return @intFromEnum(self);
        }

        pub fn toNullTerminatedString(self: *const Self, len: u64) NullTerminatedString {
            assert(isNullTerminated(self, len));
            return @enumFromInt(@intFromEnum(self));
        }

        pub fn slice(self: *const Self, len: u64) []const u8 {
            const index = self.unwrap();
            return string_bytes.items[index .. index + len];
        }

        fn isNullTerminated(self: *const Self, len: u64) bool {
            const index = self.unwrap();
            return string_bytes.items[index + len - 1] == 0;
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
            return @enumFromInt(len);
        }

        pub fn copySubstring(self: *const Self, alloc: Allocator, start_index: u32, end_index: u32) !Self {
            try Self.ensureExtraCapacity(alloc, end_index - start_index);
            return Self.initAssumeCapacity(self.slice()[start_index..end_index]);
        }

        pub fn sliceToEnd(self: *const Self) []const u8 {
            const index = self.unwrap();
            return string_bytes.items[index..];
        }

        pub fn initAddSentinel(alloc: Allocator, chars: []const u8) !Self {
            const len: u32 = @intCast(string_bytes.items.len);
            try string_bytes.appendSlice(alloc, chars);
            try string_bytes.append(alloc, 0);
            return @enumFromInt(len);
        }
    };

    const Table = struct {
        name: String,
        columns: u64,
        first_column: Index,
    };

    const Column = struct {
        name: String,
        tag: enum {
            str,
            integer,
            float,
        },
        is_primary_key: bool,
    };

    const Instruction = union(enum) {
        halt: void,
        eq: Instruction.Equal,
        neq: Instruction.Equal,

        const Equal = struct {
            lhs_reg: Index,
            rhs_reg: Index,
        };
    };

    const Register = union(enum) {
        none,
        int: i64,
        float: f64,
        string: String,
        str: []u8,
        binary: []u8,

        pub fn fromColumn(column: SQLiteColumn) Register {
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

        pub fn tag(self: Register) type {
            return std.meta.activeTag(self);
        }

        pub fn compare(self: Register, other: Register) bool {
            if (self.tag() == other.tag()) {
                return switch (self) {
                    .none => true,
                    .int => self.int == other.int,
                    .float => self.float == other.float,
                    .str => eql(u8, self.str, other.str),
                    .string => eql(u8, self.string.str(), other.string.str()),
                    .binary => unreachable, // TODO: implement
                };
            } else if (self.tag() == .str and other.tag() == .string) {
                return eql(u8, self.string.str(), other.str);
            } else if (self.tag() == .string and other.tag() == .str) {
                return eql(u8, self.str, other.string.str());
            }
            return false;
        }

        pub fn toStr(self: Register, buffer: []u8) anyerror![]u8 {
            return switch (self) {
                .none => try fmt.bufPrint(buffer, "[null]", .{}),
                .int => try fmt.bufPrint(buffer, "{d}", .{self.int}),
                .float => try fmt.bufPrint(buffer, "{e}", .{self.float}),
                .str => try fmt.bufPrint(buffer, "{s}", .{self.str}),
                .string => try fmt.bufPrint(buffer, "{s}", .{self.string.str()}),
                .binary => try fmt.bufPrint(buffer, "[binary]", .{}),
            };
        }

        pub fn toBuf(self: Register, buffer: []u8) anyerror![]u8 {
            return switch (self) {
                .none => {
                    if (buffer.len < 4) return Allocator.Error.OutOfMemory;
                    buffer[0..4].* = std.mem.toBytes(@as(u32, 0));
                    return buffer[0..4];
                },
                .int => {
                    if (buffer.len < 12) return Allocator.Error.OutOfMemory;
                    buffer[0..4].* = std.mem.toBytes(@as(u32, 1));
                    buffer[4..12].* = std.mem.toBytes(self.int);
                    return buffer[0..12];
                },
                .float => {
                    if (buffer.len < 12) return Allocator.Error.OutOfMemory;
                    buffer[0..4].* = std.mem.toBytes(@as(u32, 2));
                    buffer[4..12].* = std.mem.toBytes(self.float);
                    return buffer[0..12];
                },
                .str => {
                    if (buffer.len < self.str.len + 8) return Allocator.Error.OutOfMemory;
                    buffer[0..4].* = std.mem.toBytes(@as(u32, 3));
                    const len = self.str.len;
                    buffer[4..8].* = std.mem.toBytes(len);
                    const fmt_slice = try fmt.bufPrint(buffer[8..], "{s}", .{self.str});
                    return buffer[0 .. 8 + fmt_slice.len];
                },
                .string => {
                    if (buffer.len < self.string.len + 8) return Allocator.Error.OutOfMemory;
                    buffer[0..4].* = std.mem.toBytes(@as(u32, 3));
                    const len = self.string.len;
                    buffer[4..8].* = std.mem.toBytes(len);
                    const fmt_slice = try fmt.bufPrint(buffer[8..], "{s}", .{self.string.str()});
                    return buffer[0 .. 8 + fmt_slice.len];
                },
                .binary => {
                    if (buffer.len < self.binary.len + 8) return Allocator.Error.OutOfMemory;
                    buffer[0..4].* = std.mem.toBytes(@as(u32, 4));
                    const len = self.binary.len;
                    buffer[4..8].* = std.mem.toBytes(len);
                    @memcpy(buffer[8..], self.binary);
                    return buffer[0 .. len + 8];
                },
            };
        }
    };

    const Condition = struct {
        equality: Condition.Equality,
        lhs: union(enum) {
            column: Index, // Column index
            condition: Index, // Condition index
        },
        rhs: union(enum) {
            condition: Index,
            str: String,
            int: i64,
            float: f64,
        },

        const Equality = union(u8) {
            eq,
            ne,
            lt,
            lte,
            gt,
            gte,
        };
    };

    const Key = union(enum) {
        table: Table,
        column: Column,
        instruction: Instruction,
        register: Register,
        condition: Condition,
    };

    fn extraData(ip: *InternPool, comptime T: type, index: u32) T {
        const extra_items = ip.extra.items;
        var result: T = undefined;

        const fields = @typeInfo(T).@"struct".fields;
        inline for (fields, index..) |field, extra_index| {
            const extra_item = extra_items[extra_index];
            @field(result, field.name) = switch (field.type) {
                Index, String => @enumFromInt(extra_item),
                u32 => @bitCast(extra_item),
                else => @compileError("bad field type: " ++ @typeName(field.type)),
            };
        }

        return result;
    }
};

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

    pub fn getPageSize(self: *SQLiteDbHeader) u16 {
        return @byteSwap(self.page_size);
    }

    pub fn getVersion(self: *SQLiteDbHeader) u32 {
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

    pub fn getCellAddr(self: *SQLiteBtHeader, buffer: []u8, index: u32) u16 {
        const bt_header_size = self.getHeaderSize();
        const start = bt_header_size + (index * 2);
        const cell_adr: u16 = @byteSwap(valFromSlice(u16, buffer[start .. start + 2]));
        debug("cell adr: {d}", .{cell_adr});
        return cell_adr;
    }

    pub fn getHeaderSize(self: *SQLiteBtHeader) u8 {
        const page_type = self.getPageType();
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

    pub fn getPageType(self: *SQLiteBtHeader) u8 {
        return self.metadata[0];
    }

    pub fn getFirstFreeblock(self: *SQLiteBtHeader) u16 {
        var block: u16 = 0;
        block = @as(u16, self.metadata[1]) << 8;
        block |= self.metadata[2];
        return block;
    }

    pub fn getCellCount(self: *SQLiteBtHeader) u16 {
        var block: u16 = 0;
        block = @as(u16, self.metadata[3]) << 8;
        block |= self.metadata[4];
        return block;
    }

    pub fn getCellOffset(self: *SQLiteBtHeader) u16 {
        var block: u16 = 0;
        block = @as(u16, self.metadata[5]) << 8;
        block |= self.metadata[6];
        return block;
    }

    pub fn getFragmentCount(self: *SQLiteBtHeader) u8 {
        return self.metadata[7];
    }

    pub fn getRightChildPage(self: *SQLiteBtHeader) u32 {
        assert(self.getPageType() != 0x0D and self.getPageType() != 0x0A);
        return @byteSwap(self.right_child_page);
    }
};

// Bit masks for getVarint
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

fn getVarint(ptr1: [*]u8, result: *u64) u8 {
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
        exclamation,
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
                    '=' => {
                        token.type = .eq;
                        self.index += 1;
                        break;
                    },
                    '!' => {
                        state = .exclamation;
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
                        self.index += 1;
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
                .exclamation => switch (c) {
                    '=' => {
                        token.type = TokenType.ne;
                        self.index += 1;
                        break;
                    },
                    else => {
                        token.type = TokenType.invalid;
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

const ConditionRef = struct {
    // ConditionRef uses Element struct, value is val, tag is type of comparison, and data lhs rhs is the left right linked
    // expressions for and or. Literal comparison has the column id in the lhs
    index: u32,

    pub const ConditionEquality = enum(u32) {
        condition_and,
        condition_or,
        compare_eq,
        compare_ne,
    };

    pub const Condition = struct {
        equality: ConditionEquality,
        lhs: union(enum) {
            column_id: u32,
            condition: ConditionRef,
        },
        rhs: union(enum) {
            condition: ConditionRef,
            str: InternPool.String,
            int: i64,
            float: f64,
        },
    };

    pub fn init(index: u32) ConditionRef {
        return .{ .index = index };
    }

    pub fn unwrap(self: ConditionRef, element_list: *ElementList) ?Condition {
        if (self.index >= element_list.len) return null;
        const element = element_list.get(self.index);

        switch (element.tag) {
            .compare_eq_int, .compare_eq_str, .compare_ne_int, .compare_ne_str => return .{
                .equality = switch (element.tag) {
                    .compare_eq_str, .compare_eq_float, .compare_eq_int => .compare_eq,
                    .compare_ne_str, .compare_ne_float, .compare_ne_int => .compare_ne,
                    else => unreachable, // handled in different case
                },
                .lhs = .{ .column_id = element.data.lhs },
                .rhs = switch (element.tag) {
                    .compare_eq_str, .compare_ne_str => .{ .str = element.value.str },
                    .compare_eq_int, .compare_ne_int => .{ .int = element.value.int },
                    .compare_eq_float, .compare_ne_float => .{ .float = element.value.float },
                    else => unreachable,
                },
            },
            .compare_or, .compare_and => return .{
                .equality = switch (element.tag) {
                    .compare_and => .condition_and,
                    .compare_or => .condition_or,
                    else => unreachable,
                },
                .lhs = .{ .condition = .{ .index = element.data.lhs } },
                .rhs = .{ .condition = .{ .index = element.data.rhs } },
            },
            else => unreachable, // TODO: implement other types
        }
    }

    pub fn dump(self: *ConditionRef, element_list: *ElementList) void {
        const buf: [500]u8 = undefined;
        var fbs = io.fixedBufferStream(@constCast(&buf));
        _ = self.bufWrite(@constCast(&fbs), element_list, self.index) catch null;
        const slice = fbs.getWritten();
        print(slice.ptr, slice.len);
    }

    fn bufWrite(self: *ConditionRef, buffer: *FixedBufferStream([]u8), element_list: *ElementList, index: u32) anyerror!void {
        if (index == maxInt(u32)) {
            _ = try buffer.write("NULL");
            return;
        }
        const item: Element = element_list.get(index);
        switch (item.tag) {
            .compare_and, .compare_or => {
                switch (item.tag) {
                    .compare_and => _ = try buffer.write("(AND "),
                    .compare_or => _ = try buffer.write("(OR "),
                    else => _ = try buffer.write("( "),
                }
                try self.bufWrite(buffer, element_list, item.data.lhs);
                _ = try buffer.write(", ");
                try self.bufWrite(buffer, element_list, item.data.rhs);
                _ = try buffer.write(")");
            },
            .compare_eq_int => {
                try fmt.format(buffer.writer().any(), "(EQ COL_{d}, {d})", .{ item.data.lhs, item.value.int });
            },
            .compare_eq_str => {
                try fmt.format(buffer.writer().any(), "(EQ COL_{d}, {s})", .{ item.data.lhs, item.value.str.str() });
            },
            .compare_ne_float, .compare_ne_int, .compare_ne_str => {}, // TODO: formatting for rest of expr types
            else => {},
        }
    }
};

const SelectStmt = struct {
    columns: u64, // Each bit represents one column in the table TODO: support tables with more than 64 columns
    table: TableStmt,
    where: ?ConditionRef,
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
        str: InternPool.String,
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
    name: InternPool.String,
    first_column: u32,
    primary_column: u32,
    page: u32,

    pub fn getPrimaryKey(self: *TableStmt) u32 {
        return self.primary_column;
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

    pub fn from(elem: Element, primary: u32) TableStmt {
        assert(elem.tag == ElementType.table);
        return .{ .name = elem.value.str, .first_column = elem.data.lhs, .primary_column = primary, .page = elem.data.rhs };
    }
};

const Inst = struct {
    // In SQLite, Instructions have 6 properties: opcode, p1: u32, p2: u32, p3: u32, p4: u64 (optional?), and p5: u16.
    // For our Zig implementation, we will do a data struct with two u32 values
    // and then any instruction that requires more than 64 bits of information can be stored in extra data
    opcode: Opcode,
    data: Data,

    pub const Opcode = enum(u8) {
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
        eq,
        neq,
        string,
        int,
        float,
    };
};

const SQLiteDbTable = struct {
    page: u32,
    sql: InternPool.String,
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
        var row_id: u64 = 0;

        // TODO: this only supports 0x0d pages. Support the other pages
        cursor += getVarint(buffer.ptr, &cell_size);
        cursor += getVarint(buffer.ptr + cursor, &row_id);

        // The cell header size in bytes is part of the header size and therefore also part of the cell size.
        // However, we can read this once and then subtract it from the other sizes
        const cell_header_int_size_bytes = getVarint(buffer.ptr + cursor, &cell_header_size);

        cell_header_size -= cell_header_int_size_bytes;
        cell_size -= cell_header_int_size_bytes;
        cursor += cell_header_int_size_bytes;

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
        self.header_cursor += getVarint(self.buffer.ptr + self.header_cursor, &header_val);

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
        self.header_cursor += getVarint(self.buffer.ptr + self.header_cursor, &header_val);

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
        const page_size = header.getPageSize();
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

        var cell_index: u32 = 0;
        while (cell_index < bt_header.getCellCount()) : (cell_index += 1) {
            const cell_adr = bt_header.getCellAddr(new_slice[sqlite_header_size..], cell_index);
            const cell_start = new_slice[cell_adr..];

            var record = SQLiteRecord.from(cell_start);
            debug("table record: {}", .{record});
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
                            const sql_str = try InternPool.String.initAddSentinel(alloc, sql_col.text, 0);
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
        from_after,
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
        where_andor,
        where_equality,
        where_lhs,
        where_rhs,
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

    fn replaceNameAtIndex(self: *ASTGen, index: u32, name: InternPool.String) void {
        self.element_list.items(.value)[index] = .{
            .str = name,
        };
    }

    fn addToken(self: *ASTGen, token: MinimizedToken) Allocator.Error!u32 {
        const result = @as(u32, @intCast(self.token_list.len));
        try self.token_list.append(self.gpa, token);
        return result;
    }

    fn buildCreateTable(self: *ASTGen, sqlite_table: SQLiteDbTable) Error!TableStmt {
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
        var name: ?InternPool.String = null;
        var tag: ?ElementType = null;
        var primary_key: PrimaryKeyState = PrimaryKeyState.unfilled;
        var col_count: u32 = 0;
        var col_index: u32 = 0;
        var table_index: ?u32 = null;
        var primary_key_index: u32 = 0;

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
                                .data = .{ .lhs = maxInt(u32), .rhs = sqlite_table.page },
                            });
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
                            const rhs: u32 = if (primary_key == PrimaryKeyState.current) 1 else 0;
                            const new_index = try self.addElement(.{
                                .value = .{ .str = name.? },
                                .tag = tag.?,
                                .data = .{ .lhs = maxInt(u32), .rhs = rhs },
                            });
                            const data = self.getElementData(col_index);
                            self.replaceDataAtIndex(col_index, .{ .lhs = new_index, .rhs = data.rhs });
                            col_index = new_index;
                            if (primary_key == PrimaryKeyState.current) {
                                primary_key_index = col_count - 1;
                                primary_key = PrimaryKeyState.filled;
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
                    return TableStmt.from(self.element_list.get(table_index.?), primary_key_index);
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
        var where: ?ConditionRef = null;
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
                            state = .from_after;
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
                                table = try self.buildCreateTable(sqlite_table);
                                state = .select_second;
                                self.index = column_list_index - 1;
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
                .from_after => {
                    switch (token.tag) {
                        .keyword_where => {
                            where = try self.buildWhereClause(table.?);
                            where.?.dump(self.element_list);
                        },
                        else => break,
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
            .where = where,
        };
    }

    pub fn buildWhereClause(self: *ASTGen, table: TableStmt) Error!?ConditionRef {
        var state: State = .where;
        var equality: ?TokenType = null;
        var col_index: ?u32 = null;
        var last_element_andor = false;
        var expr_index: ?u32 = null;
        var expr_prev_index: ?u32 = null;
        var expr_first_index: ?u32 = null;
        while (self.index < self.token_list.len) : (self.index += 1) {
            const token = self.token_list.get(self.index);
            switch (state) {
                // TODO: support nested parenthesis
                .where => {
                    state = .where_lhs;
                },
                .where_lhs => switch (token.tag) {
                    .word => {
                        const column_name = ASTGen.getTokenSource(self.source, token);
                        col_index = table.getColumnIndex(self.element_list, column_name);
                        state = .where_equality;
                    },
                    .keyword_and, .keyword_or => {
                        if (last_element_andor or expr_index == null) {
                            break;
                        }
                        const replace_first_expr = expr_first_index == expr_index;
                        const expr_prev_temp_index = expr_index;
                        expr_index = try self.addElement(.{
                            .value = undefined,
                            .tag = switch (token.tag) {
                                .keyword_and => ElementType.compare_and,
                                .keyword_or => ElementType.compare_or,
                                else => break,
                            },
                            .data = .{ .lhs = expr_index.?, .rhs = maxInt(u32) },
                        });
                        last_element_andor = true;
                        if (expr_prev_index) |expr| {
                            const data = self.getElementData(expr);
                            self.replaceDataAtIndex(expr, .{ .lhs = data.lhs, .rhs = expr_index.? });
                        }
                        expr_prev_index = expr_prev_temp_index;
                        if (replace_first_expr) {
                            expr_first_index = expr_index;
                        }
                    },
                    else => {
                        if (last_element_andor) {
                            break;
                        }
                        if (expr_first_index) |index| {
                            return .{ .index = index };
                        }
                        break;
                    },
                },
                .where_equality => switch (token.tag) {
                    .eq, .ne => {
                        equality = token.tag;
                        state = .where_rhs;
                    },
                    else => break,
                },
                .where_rhs => {
                    debug("where_rhs eq: {?}, col_index: {d}", .{ equality, col_index.? });
                    if (equality == null or col_index == null) {
                        debug("where_rhs missing", .{});
                        return Error.InvalidSyntax;
                    }
                    switch (token.tag) {
                        .double_quote_word => {
                            const string_literal = ASTGen.getTokenSource(self.source, token);
                            debug("where_rhs literal: {s}", .{string_literal});
                            const value = try InternPool.String.init(self.gpa, string_literal[1 .. string_literal.len - 1]);
                            expr_prev_index = expr_index;
                            expr_index = try self.addElement(.{
                                .value = .{ .str = value },
                                .tag = switch (equality.?) {
                                    .eq => ElementType.compare_eq_str,
                                    .ne => ElementType.compare_ne_str,
                                    else => return Error.InvalidSyntax,
                                },
                                .data = .{ .lhs = col_index.?, .rhs = maxInt(u32) },
                            });
                        },
                        .integer => {
                            const slice = ASTGen.getTokenSource(self.source, token);
                            const value = fmt.parseInt(i64, slice, 10) catch break;
                            expr_prev_index = expr_index;
                            expr_index = try self.addElement(.{
                                .value = .{ .int = value },
                                .tag = switch (equality.?) {
                                    .eq => ElementType.compare_eq_int,
                                    .ne => ElementType.compare_ne_int,
                                    else => return Error.InvalidSyntax,
                                },
                                .data = .{ .lhs = col_index.?, .rhs = maxInt(u32) },
                            });
                        },
                        else => break,
                    }
                    last_element_andor = false;
                    if (expr_prev_index) |expr| {
                        const data = self.getElementData(expr);
                        self.replaceDataAtIndex(expr, .{ .lhs = data.lhs, .rhs = expr_index.? });
                    } else {
                        expr_first_index = expr_index;
                    }
                    equality = null;
                    col_index = null;
                    state = .where_lhs;
                },
                else => break,
            }
        }
        return Error.InvalidSyntax;
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
    name: InternPool.String,

    pub fn from(element_list: *ElementList, table_stmt: *const TableStmt) TableMetadataReader {
        return .{
            .element_list = element_list,
            .index = table_stmt.first_column,
            .name = table_stmt.name,
        };
    }

    pub fn next(self: *TableMetadataReader) ?InternPool.Column {
        if (self.index >= self.element_list.len or self.index == maxInt(u32)) {
            return null;
        }
        const element = self.element_list.get(self.index);
        self.index = element.data.lhs;
        return InternPool.Column.fromElement(element);
    }
};

const ConditionTraversal = struct {
    element_list: *ElementList,
    index: u32,
    current_condition: ConditionRef.ConditionEquality,
    stack: ArrayListUnmanaged(u32),
    last_pop: ConditionRef,

    pub fn init(element_list: *ElementList, index: u32) ConditionTraversal {
        return .{
            .element_list = element_list,
            .index = index,
            .current_condition = .condition_or,
            .stack = .{},
            .last_pop = .{ .index = maxInt(u32) },
        };
    }

    pub fn next(self: *ConditionTraversal, alloc: Allocator) Allocator.Error!?ConditionRef.Condition {
        var curr_ref: ConditionRef = .{ .index = self.index };
        debug("next condition: {d}", .{curr_ref.index});
        while (true) {
            if (curr_ref.unwrap(self.element_list)) |cond| {
                switch (cond.equality) {
                    .condition_or, .condition_and => {
                        try self.stack.append(alloc, curr_ref.index);
                        curr_ref = cond.lhs.condition;
                        self.current_condition = cond.equality;
                    },
                    .compare_eq, .compare_ne => {
                        self.index = maxInt(u32);
                        return cond;
                    },
                }
            } else {
                if (self.stack.items.len == 0) return null;
                self.last_pop = .{ .index = self.stack.pop() };
                debug("last pop: {d}", .{self.last_pop.index});
                curr_ref = self.last_pop.unwrap(self.element_list).?.rhs.condition;
            }
        }
        return null;
    }

    pub fn deint(self: *ConditionTraversal, alloc: Allocator) void {
        self.stack.deinit(alloc);
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

    fn addInst(self: *InstGen, inst: Inst) Allocator.Error!u32 {
        const result = @as(u32, @intCast(self.inst_list.len));
        try self.inst_list.append(self.gpa, inst);
        return result;
    }

    fn replaceDataAtIndex(self: *InstGen, index: u32, data: Data) void {
        self.inst_list.items(.data)[index] = data;
    }

    fn replaceOpcodeAtIndex(self: *InstGen, index: u32, opcode: Inst.Opcode) void {
        self.inst_list.items(.opcode)[index] = opcode;
    }

    fn getDataAtIndex(self: *InstGen, index: u32) Data {
        return self.inst_list.items(.data)[index];
    }

    fn getOpcodeAtIndex(self: *InstGen, index: u32) Inst.Opcode {
        return self.inst_list.items(.opcode)[index];
    }

    fn addExtra(self: *InstGen, extra_data: anytype) Allocator.Error!u32 {
        const fields = meta.fields(@TypeOf(extra_data));
        try extra.ensureUnusedCapacity(self.gpa, fields.len);
        const extra_index: u32 = @intCast(extra.items.len);
        extra.items.len += fields.len;
        var i = extra_index;
        inline for (fields) |field| {
            extra.items[i] = @field(extra_data, field.name);
            i += 1;
        }
        return extra_index;
    }

    fn markInst(self: *InstGen, opcode: Inst.Opcode) Error!u32 {
        return try self.addInst(.{ .opcode = opcode, .data = .{ .lhs = 0, .rhs = 0 } });
    }

    fn instInit(self: *InstGen, index: u32, start_inst: u32) void {
        self.replaceDataAtIndex(index, .{ .lhs = start_inst, .rhs = 0 });
    }

    fn openRead(self: *InstGen, index: u32, table_index: u32) void {
        self.replaceDataAtIndex(index, .{ .lhs = table_index, .rhs = 0 });
        self.cursor_count += 1;
    }

    // The next use of the Rowid or Column or Next instruction for P1 will refer to the first entry in the database table or index.
    // If the table or index is empty, jump immediately to P2. If the table or index is not empty, fall through to the following instruction.
    // If P2 is zero, that is an assertion that the P1 table is never empty and hence the jump will never be taken.
    // This opcode leaves the cursor configured to move in forward order, from the beginning toward the end. In other words, the cursor is configured to use Next, not Prev.
    fn rewind(self: *InstGen, index: u32, end_inst: u32) void {
        self.replaceDataAtIndex(index, .{ .lhs = end_inst, .rhs = 0 });
    }

    // Store in register P2 an integer which is the key of the table entry that P1 is currently point to.
    // P1 can be either an ordinary table or a virtual table. There used to be a separate OP_VRowid opcode for use with virtual tables,
    // but this one opcode now works for both table types.
    fn rowId(self: *InstGen, read_cursor: u32, store_reg: u32) Error!void {
        _ = try self.addInst(.{ .opcode = .row_id, .data = .{ .lhs = read_cursor, .rhs = store_reg } });
    }

    // Interpret the data that cursor P1 points to as a structure built using the MakeRecord instruction. Extract the P2-th column from this record.
    // If there are less than (P2+1) values in the record, extract a NULL.
    // The value extracted is stored in register P3.
    // If the record contains fewer than P2 fields, then extract a NULL. Or, if the P4 argument is a P4_MEM use the value of the P4 argument as the result.
    fn column(self: *InstGen, read_cursor: u32, store_reg: u32, col_num: u32) Error!void {
        const extra_index = try self.addExtra(.{ .store_reg = store_reg, .col_num = col_num });
        _ = try self.addInst(.{ .opcode = .column, .data = .{ .lhs = read_cursor, .rhs = extra_index } });
    }

    fn eq(self: *InstGen, lhs_reg: u32, rhs_reg: u32) Error!void {
        const extra_index = try self.addExtra(.{ .lhs_reg = lhs_reg, .rhs_reg = rhs_reg });
        _ = try self.addInst(.{ .opcode = .eq, .data = .{ .lhs = 0, .rhs = extra_index } });
    }

    fn neq(self: *InstGen, lhs_reg: u32, rhs_reg: u32) Error!void {
        const extra_index = try self.addExtra(.{ .lhs_reg = lhs_reg, .rhs_reg = rhs_reg });
        _ = try self.addInst(.{ .opcode = .neq, .data = .{ .lhs = 0, .rhs = extra_index } });
    }

    fn eqReplaceJump(self: *InstGen, index: u32, jump_address: u32) void {
        const data = self.getDataAtIndex(index);
        self.replaceDataAtIndex(index, .{ .lhs = jump_address, .rhs = data.rhs });
    }

    fn eqNegate(self: *InstGen, index: u32) void {
        const opcode = self.getOpcodeAtIndex(index);
        self.replaceOpcodeAtIndex(index, switch (opcode) {
            .neq => .eq,
            .eq => .neq,
            else => opcode,
        });
    }

    fn string(self: *InstGen, str: InternPool.String, store_reg: u32) Error!void {
        const extra_index = try self.addExtra(str);
        _ = try self.addInst(.{ .opcode = .string, .data = .{ .lhs = store_reg, .rhs = extra_index } });
    }

    fn integer(self: *InstGen, int: i64, store_reg: u32) Error!void {
        const uint: u64 = @intCast(int);
        const extra_index = try self.addExtra(.{ .upper = @as(u32, @truncate(uint >> 8)), .lower = @as(u32, @truncate(uint)) });
        _ = try self.addInst(.{ .opcode = .int, .data = .{ .lhs = store_reg, .rhs = extra_index } });
    }

    // The registers P1 through P1+P2-1 contain a single row of results. This opcode causes the sqlite3_step() call to terminate with an SQLITE_ROW return code
    // and it sets up the sqlite3_stmt structure to provide access to the r(P1)..r(P1+P2-1) values as the result row.
    fn resultRow(self: *InstGen, reg_index_start: u32, reg_index_end: u32) Error!void {
        _ = try self.addInst(.{ .opcode = .result_row, .data = .{ .lhs = reg_index_start, .rhs = reg_index_end } });
    }

    fn next(self: *InstGen, cursor: u32, success_jump: u32) Error!void {
        _ = try self.addInst(.{ .opcode = .next, .data = .{ .lhs = cursor, .rhs = success_jump } });
    }

    fn halt(self: *InstGen) Error!void {
        _ = try self.addInst(.{ .opcode = .halt, .data = .{ .lhs = 0, .rhs = 0 } });
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
        _ = try self.addInst(.{ .opcode = .transaction, .data = .{ .lhs = database_id, .rhs = write_int } });
    }

    fn goto(self: *InstGen, inst_jump: u32) Error!void {
        _ = try self.addInst(.{ .opcode = .goto, .data = .{ .lhs = inst_jump, .rhs = 0 } });
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
                var reg_count: u32 = 1;
                var reader = TableMetadataReader.from(self.element_list, &select.table);
                const where_clause = select.where;
                const compare_reg = reg_count;
                var final_comparison: u32 = 0;
                if (where_clause) |ref| {
                    var traversal = ConditionTraversal.init(self.element_list, ref.index);
                    defer traversal.deint(self.gpa);
                    var comparisons: ArrayListUnmanaged(u32) = .{};
                    var columns_start = self.inst_list.len;
                    defer comparisons.deinit(self.gpa);
                    while (try traversal.next(self.gpa)) |cond| {
                        try self.column(cursor, compare_reg, cond.lhs.column_id);
                        reg_count += 1;
                        switch (traversal.current_condition) {
                            .condition_or => {
                                if (cond.equality == .compare_eq) {
                                    try self.eq(compare_reg, reg_count);
                                } else {
                                    try self.neq(compare_reg, reg_count);
                                }
                                try comparisons.append(self.gpa, self.inst_list.len - 1);
                            },
                            else => return Error.InvalidSyntax, // TODO: implement and clause
                        }
                    } else {
                        columns_start = self.inst_list.len;
                    }
                    for (comparisons.items, 0..) |value, i| {
                        if (i == comparisons.items.len - 1) {
                            self.eqNegate(value);
                            final_comparison = value;
                        } else {
                            self.eqReplaceJump(value, columns_start);
                        }
                    }
                }
                var output_count: u32 = reg_count;
                while (reader.next()) |col| {
                    // TODO: support more than 64 columns
                    if (select.columns & (@as(u64, 0x1) << @truncate(col_count)) > 0) {
                        if (col.is_primary_key and col.tag == .integer) {
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
                try self.resultRow(reg_count + 1, output_count + 1);
                try self.next(cursor, rewind_start);
                const next_index = self.inst_list.len - 1;
                try self.halt();
                const halt_index = self.inst_list.len - 1;
                // TODO: support multiples databases, writing to tables
                try self.transaction(0, false);
                const transaction_index = self.inst_list.len - 1;
                if (where_clause) |where| {
                    self.eqReplaceJump(final_comparison, next_index);
                    var traversal = ConditionTraversal.init(self.element_list, where.index);
                    var store_reg = compare_reg + 1;
                    defer traversal.deint(self.gpa);
                    while (try traversal.next(self.gpa)) |cond| {
                        switch (cond.rhs) {
                            .str => try self.string(cond.rhs.str, store_reg),
                            .int => try self.integer(cond.rhs.int, store_reg),
                            else => return Error.InvalidSyntax, // TODO: implement float
                        }
                        store_reg += 1;
                    }
                }
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
    reg_list: ArrayListUnmanaged(InternPool.Register),
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

    fn reg(self: *Vm, index: u32, register: InternPool.Register) Error!void {
        debug("reg index: {d}, len: {d}", .{ index, self.reg_list.items.len });
        // registers start at 1, not 0
        if (index - 1 == self.reg_list.items.len) {
            try self.reg_list.append(self.gpa, register);
        } else {
            while (index > self.reg_list.items.len) {
                try self.reg_list.append(self.gpa, InternPool.Register.none);
            }
            self.reg_list.items[index - 1] = register;
        }
    }

    // TODO: do not reference instruction list or extra data directly. Have them go through a layer and provide a struct with field names.
    // That way don't have to figure out data.lhs/rhs for each instruction
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
            debug("inst: {s}", .{@tagName(instruction.opcode)});
            switch (instruction.opcode) {
                .init => {
                    self.pc = instruction.data.lhs;
                },
                .open_read => {
                    const page_index = instruction.data.lhs;
                    buffer = self.db.readPage(page_index);
                    debug("buffer created", .{});
                    header = SQLiteBtHeader.from(buffer.?);
                    // TODO: refactor this mess
                    cell_size = header.?.getCellCount();
                    debug("cell size: {d}", .{cell_size});
                    if (cell_size != 0) {
                        const addr = header.?.getCellAddr(buffer.?, cell_count);
                        debug("cell address: {x}", .{addr});
                        record = SQLiteRecord.from(buffer.?[addr..]);
                    }
                    self.pc += 1;
                },
                .rewind => {
                    const end_inst = instruction.data.lhs;
                    if (record != null) {
                        col_value = record.?.next();
                        if (col_value == null) {
                            break;
                        }
                        col_count += 1;
                        self.pc += 1;
                    } else {
                        debug("table is empty", .{});
                        self.pc = end_inst;
                    }
                },
                .row_id => {
                    assert(record != null);
                    debug("row_id SQLiteColumn: {d}", .{record.?.row_id});
                    try self.reg(instruction.data.rhs, InternPool.Register{ .int = @intCast(record.?.row_id) });
                    self.pc += 1;
                },
                .column => {
                    assert(record != null);
                    const extra_index = instruction.data.rhs;
                    const store_reg = extra.items[extra_index];
                    const col = extra.items[extra_index + 1];
                    if (col_count > col) {
                        record.?.reset();
                        col_count = 0;
                    }
                    while (col_count < col) : (col_count += 1) {
                        record.?.consume();
                    }
                    col_value = record.?.next();
                    col_count += 1;
                    assert(col_value != null);
                    try self.reg(store_reg, InternPool.Register.fromColumn(col_value.?));
                    col_value = record.?.next();
                    debug("col_value: {?}", .{col_value});
                    col_count += 1;
                    self.pc += 1;
                },
                .result_row => {
                    const start_reg = instruction.data.lhs;
                    const end_reg = instruction.data.rhs;

                    // TODO: refactor this mess. Probably own struct for writing..
                    var i = start_reg;
                    const len: u32 = end_reg - start_reg;
                    var write_buf: [256]u8 = undefined;
                    var row_buf: [512]u8 = undefined;
                    var row_buf_written: u32 = 4;
                    var write_count: u8 = 0;
                    row_buf[0..4].* = std.mem.toBytes(len);
                    while (i < end_reg) : (i += 1) {
                        const cur_reg = self.reg_list.items[i - 1];
                        const written = cur_reg.toStr(@constCast(write_buf[write_count..])) catch write_buf[write_count..];
                        const written_row = cur_reg.toBuf(row_buf[row_buf_written..]) catch row_buf[row_buf_written..];
                        row_buf_written += written_row.len;
                        const written_len: u8 = @intCast(written.len);
                        debug("written len: {d}", .{written_len});
                        write_count += written_len;
                        if (i != end_reg - 1) {
                            write_buf[write_count] = '|';
                            write_count += 1;
                        }
                    }
                    print(write_buf[0..write_count].ptr, write_buf[0..write_count].len);
                    renderRow(row_buf[0..row_buf_written].ptr, row_buf[0..row_buf_written].len);
                    self.pc += 1;
                },
                .neq, .eq => {
                    const jump_address = instruction.data.lhs;
                    const extra_index = instruction.data.rhs;
                    const lhs_reg_index = extra.items[extra_index];
                    const rhs_reg_index = extra.items[extra_index + 1];
                    const lhs_reg = self.reg_list.items[lhs_reg_index - 1];
                    const rhs_reg = self.reg_list.items[rhs_reg_index - 1];
                    const equal_values: bool = lhs_reg.compare(rhs_reg);

                    if ((instruction.opcode == .eq and equal_values) or (instruction.opcode == .neq and !equal_values)) {
                        self.pc = jump_address;
                        debug("jump: {d}", .{jump_address});
                    } else {
                        self.pc += 1;
                    }
                },
                .string => {
                    const store_reg = instruction.data.lhs;
                    const extra_index = instruction.data.rhs;
                    const str_index = extra.items[extra_index];
                    const str_len = extra.items[extra_index + 1];
                    try self.reg(store_reg, .{ .string = .{ .index = str_index, .len = str_len } });
                    self.pc += 1;
                },
                .int => {
                    const store_reg = instruction.data.lhs;
                    const extra_index = instruction.data.rhs;
                    const int_upper = extra.items[extra_index];
                    const int_lower = extra.items[extra_index + 1];
                    const int: i64 = (int_upper << 8) + int_lower;
                    try self.reg(store_reg, .{ .int = int });
                    self.pc += 1;
                },
                .next => {
                    debug("col_value: {?}", .{col_value});
                    if (cell_count >= cell_size - 1) {
                        self.pc += 1;
                    } else {
                        cell_count += 1;

                        const addr = header.?.getCellAddr(buffer.?, cell_count);
                        debug("cell address: {x}", .{addr});
                        record = SQLiteRecord.from(buffer.?[addr..]);
                        col_value = record.?.next();

                        const inst_addr = instruction.data.lhs;
                        self.pc = inst_addr;
                    }
                },
                .halt => break,
                .transaction => {
                    // TODO: support transactions, attached databases, writing
                    self.pc += 1;
                },
                .goto => {
                    self.pc = instruction.data.lhs;
                },
                else => debug("instruction not implemented: {}", .{instruction.opcode}),
            }
        }
    }
};

const MinimizedToken = struct { tag: TokenType, start: u32 };

// TODO: put all these into a self-contained structure like how the Zig compiler does with InternPool
// Then only return the filled out structures, not the data oriented design ones
var string_bytes: ArrayListUnmanaged(u8) = .{};
var extra: ArrayListUnmanaged(u32) = .{};
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

    debug("building instructions", .{});
    try inst_gen.buildInstructions();
    debug("inst generated!", .{});

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
