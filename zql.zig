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

const PackedU64 = packed struct {
    a: u32,
    b: u32,

    pub fn unwrap(self: PackedU64) u64 {
        return @bitCast(self);
    }

    pub fn init(ty: anytype) PackedU64 {
        comptime assert(@sizeOf(@TypeOf(ty)) == @sizeOf(PackedU64));
        return @bitCast(ty);
    }
};

const InternPool = struct {
    items: MultiArrayList(Item),
    instructions: MultiArrayList(InstItem),
    extra: ArrayListUnmanaged(u32),
    string_bytes: ArrayListUnmanaged(u8),

    pub fn init() InternPool {
        return .{
            .items = .{},
            .instructions = .{},
            .extra = .{},
            .string_bytes = .{},
        };
    }

    pub fn deinit(ip: *InternPool, alloc: Allocator) void {
        ip.items.deinit(alloc);
        ip.instructions.deinit(alloc);
        ip.extra.deinit(alloc);
        ip.string_bytes.deinit(alloc);
    }

    const Tag = enum(u8) {
        table,
        column,
        cursor,
        condition_or,
        condition_and,
        condition_lte_int,
        condition_lte_float,
        condition_lt_int,
        condition_lt_float,
        condition_gt_int,
        condition_gt_float,
        condition_gte_int,
        condition_gte_float,
        condition_eq_int,
        condition_eq_float,
        condition_eq_string,
        condition_ne_int,
        condition_ne_float,
        condition_ne_string,
    };

    const Item = struct {
        tag: Tag,
        data: u32,
    };

    const Opcode = enum(u8) {
        eq,
        neq,
        row_id,
        goto,
        halt,
        open_read,
        init,
        string,
        integer,
        result_row,
        next,
        rewind,
        column,
        transaction,
    };

    const InstItem = struct {
        opcode: Opcode,
        data: u32,
    };

    const Index = enum(u32) {
        _,
        pub fn toOptional(dep: InternPool.Index) Optional {
            return @enumFromInt(@intFromEnum(dep));
        }
        pub const Optional = enum(u32) {
            none = maxInt(u32),
            _,
            pub fn unwrap(opt: Optional) ?InternPool.Index {
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

        pub fn slice(string: OptionalString, len: u64, ip: *const InternPool) ?[]const u8 {
            return (string.unwrap() orelse return null).slice(len, ip);
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

        pub fn slice(self: *const Self, ip: *InternPool) [:0]const u8 {
            const string = self.toString();
            const index = string.unwrap();
            const full_slice = string.sliceToEnd(ip);
            return ip.string_bytes.items[index .. index + std.mem.indexOfScalar(u8, full_slice, 0).? :0];
        }

        pub fn initAddSentinel(alloc: Allocator, chars: []const u8, ip: *InternPool) !Self {
            const len: u32 = @intCast(ip.string_bytes.items.len);
            try ip.string_bytes.appendSlice(alloc, chars);
            try ip.string_bytes.append(alloc, 0);
            return @enumFromInt(len);
        }
    };

    const String = enum(u32) {
        /// An empty string.
        empty = 0,
        _,

        const Self = @This();

        fn unwrap(self: Self) u32 {
            return @intFromEnum(self);
        }

        pub fn toNullTerminatedString(self: Self, len: u64) NullTerminatedString {
            assert(isNullTerminated(self, len));
            return @enumFromInt(@intFromEnum(self));
        }

        pub fn slice(self: Self, len: u64, ip: *InternPool) []const u8 {
            const index = self.unwrap();
            return ip.string_bytes.items[index .. index + @as(u32, @intCast(len))];
        }

        fn isNullTerminated(self: Self, len: u64, ip: *InternPool) bool {
            const index = self.unwrap();
            return ip.string_bytes.items[index + len - 1] == 0;
        }

        pub fn initAssumeCapacity(chars: []const u8, ip: *InternPool) Self {
            const len: u32 = @intCast(ip.string_bytes.items.len);
            ip.string_bytes.appendSliceAssumeCapacity(chars);
            return @enumFromInt(len);
        }

        pub fn ensureExtraCapacity(alloc: Allocator, additional_count: u32, ip: *InternPool) !void {
            try ip.string_bytes.ensureUnusedCapacity(alloc, additional_count);
        }

        pub fn init(alloc: Allocator, chars: []const u8, ip: *InternPool) !Self {
            const len: u32 = @intCast(ip.string_bytes.items.len);
            try ip.string_bytes.appendSlice(alloc, chars);
            return @enumFromInt(len);
        }

        pub fn copySubstring(self: Self, alloc: Allocator, start_index: u32, end_index: u32, ip: *InternPool) !Self {
            try Self.ensureExtraCapacity(alloc, end_index - start_index);
            return Self.initAssumeCapacity(self.slice(end_index - start_index + 1, ip)[start_index..end_index], ip);
        }

        pub fn copySubstringNullTerminate(self: Self, alloc: Allocator, start_index: u32, end_index: u32, ip: *InternPool) !NullTerminatedString {
            try Self.ensureExtraCapacity(alloc, end_index - start_index + 1, ip);
            const len: u32 = @intCast(ip.string_bytes.items.len);
            const chars = self.slice(end_index, ip)[start_index..end_index];
            ip.string_bytes.appendSliceAssumeCapacity(chars);
            ip.string_bytes.appendAssumeCapacity(0);
            return @enumFromInt(len);
        }

        pub fn sliceToEnd(self: Self, ip: *InternPool) []const u8 {
            const index = self.unwrap();
            return ip.string_bytes.items[index..];
        }
    };

    const Table = struct {
        name: NullTerminatedString,
        page: u32,
        first_column: Index.Optional,

        const Repr = struct {
            name: NullTerminatedString,
            page: u32,
            first_column: Index.Optional,
        };
    };

    const Column = struct {
        name: NullTerminatedString,
        id: u32,
        next_column: Index.Optional,
        tag: Column.Tag,
        is_primary_key: bool,

        const Tag = enum(u3) {
            text,
            integer,
            real,
            null,
            blob,
        };

        const Repr = struct {
            name: NullTerminatedString,
            next_column: Index.Optional,
            flags: u32,
        };

        const Flags = packed struct {
            tag: u3,
            is_primary_key: bool,
            id: u28, // If more flags are necessary, this can be shortened
        };
    };

    pub fn columnFromName(ip: *InternPool, table: Index, col_name: []const u8) ?struct { index: InternPool.Index, count: u32 } {
        const table_key = ip.indexToKey(table).table;
        var col_index_optional = table_key.first_column;
        var col_count: u32 = 0;
        while (col_index_optional.unwrap()) |col_index| {
            const col_key = ip.indexToKey(col_index).column;
            debug("columnFromName: {s} == {s}", .{ col_key.name.slice(ip), col_name });
            if (eql(u8, col_key.name.slice(ip), col_name)) {
                return .{ .index = col_index, .count = col_count };
            }
            col_count += 1;
            col_index_optional = col_key.next_column;
        }
        return null;
    }

    pub fn peekInst(ip: *InternPool) InstIndex {
        const len = ip.instructions.len;
        if (len == 0) {
            return InstIndex.none;
        }
        return @enumFromInt(len);
    }

    pub fn addInst(ip: *InternPool, alloc: Allocator, key: Instruction) Allocator.Error!InstIndex {
        const index: u32 = try ip.instructions.addOne(alloc);
        // Each data index in extra is 4 bytes. So we bit shift to the right by 2 (4 bytes) to determine how many 32 bit extra indices we need.
        const size: u32 = key.size() >> 2;
        if (size > 1) {
            const extra_index: u32 = ip.extra.items.len;
            try ip.extra.appendNTimes(alloc, 0, size);
            ip.instructions.set(index, .{ .opcode = key.opcode(), .data = extra_index });
        }
        const index_enum: InstIndex = @enumFromInt(index);
        ip.setInst(index_enum, key);
        return index_enum;
    }

    pub fn setInst(ip: *InternPool, index: InstIndex, key: Instruction) void {
        const opcode = key.opcode();
        const index_int: u32 = @intFromEnum(index);
        debug("setInst: {}, index: {d}, size: {d}, key: {}", .{ opcode, index_int, key.size(), key });
        switch (key.size()) {
            0 => {
                ip.instructions.set(index_int, .{ .opcode = opcode, .data = 0 });
            },
            4 => {
                switch (key) {
                    .init => |init_inst| {
                        ip.instructions.set(index_int, .{ .opcode = opcode, .data = @intFromEnum(init_inst) });
                    },
                    .goto => |goto_inst| {
                        ip.instructions.set(index_int, .{ .opcode = opcode, .data = @intFromEnum(goto_inst) });
                    },
                    .open_read => |table_index| {
                        ip.instructions.set(index_int, .{ .opcode = opcode, .data = @intFromEnum(table_index) });
                    },
                    else => unreachable, // Not a 4 byte payload instruction
                }
            },
            else => {
                const extra_index: u32 = ip.instructions.get(index_int).data;
                switch (key) {
                    .eq, .neq => |extra_data| {
                        ip.insertExtra(extra_index, extra_data);
                    },
                    .rewind => |extra_data| {
                        ip.insertExtra(extra_index, extra_data);
                    },
                    .row_id => |extra_data| {
                        ip.insertExtra(extra_index, extra_data);
                    },
                    .result_row => |extra_data| {
                        ip.insertExtra(extra_index, extra_data);
                    },
                    .column => |extra_data| {
                        ip.insertExtra(extra_index, extra_data);
                    },
                    .next => |extra_data| {
                        ip.insertExtra(extra_index, extra_data);
                    },
                    .transaction => |extra_data| {
                        ip.insertExtra(extra_index, extra_data.pack());
                    },
                    .string => |extra_data| {
                        ip.insertExtra(extra_index, extra_data);
                    },
                    .integer => |extra_int| {
                        ip.insertExtra(extra_index, extra_int.pack());
                    },
                    else => unreachable,
                }
                ip.instructions.set(index_int, .{ .opcode = opcode, .data = extra_index });
            },
        }
    }

    pub fn getInst(ip: *InternPool, index: InstIndex) ?Instruction {
        const unwrap = index.unwrap();
        if (unwrap == null or unwrap.? >= ip.instructions.len) {
            return null; // TODO: throw an error instead?
        }
        const item = ip.instructions.get(unwrap.?);
        debug("getInst: {}, {d}", .{ item.opcode, item.data });
        switch (item.opcode) {
            .init => return .{ .init = @enumFromInt(item.data) },
            .halt => return Instruction.halt,
            .eq => {
                const extra_data = ip.extraData(Instruction.Equal, item.data);
                return .{ .eq = extra_data };
            },
            .neq => {
                const extra_data = ip.extraData(Instruction.Equal, item.data);
                return .{ .neq = extra_data };
            },
            .open_read => return .{ .open_read = @enumFromInt(item.data) },
            .goto => return .{ .goto = @enumFromInt(item.data) },
            .rewind => {
                const extra_data = ip.extraData(Instruction.Rewind, item.data);
                return .{ .rewind = extra_data };
            },
            .row_id => {
                const extra_data = ip.extraData(Instruction.RowId, item.data);
                return .{ .row_id = extra_data };
            },
            .result_row => {
                const extra_data = ip.extraData(Instruction.ResultRow, item.data);
                return .{ .result_row = extra_data };
            },
            .column => {
                const extra_data = ip.extraData(Instruction.Column, item.data);
                return .{ .column = extra_data };
            },
            .next => {
                const extra_data = ip.extraData(Instruction.Next, item.data);
                return .{ .next = extra_data };
            },
            .transaction => {
                const extra_data = ip.extraData(Instruction.Transaction.Repr, item.data);
                return .{ .transaction = extra_data.unpack() };
            },
            .string => {
                const extra_data = ip.extraData(Instruction.String, item.data);
                return .{ .string = extra_data };
            },
            .integer => {
                const extra_data = ip.extraData(Instruction.Integer.Repr, item.data);
                return .{ .integer = extra_data.unpack() };
            },
        }
    }

    const InstIndex = enum(u32) {
        none = std.math.maxInt(u32),
        _,
        pub fn unwrap(opt: InstIndex) ?u32 {
            return switch (opt) {
                .none => return null,
                _ => @intFromEnum(opt),
            };
        }

        pub fn increment(opt: InstIndex) InstIndex {
            return switch (opt) {
                .none => @enumFromInt(0),
                else => @enumFromInt(@intFromEnum(opt) + 1),
            };
        }
    };

    const Instruction = union(enum) {
        init: InstIndex,
        halt: void,
        eq: Instruction.Equal,
        neq: Instruction.Equal,
        goto: InstIndex,
        row_id: Instruction.RowId,
        rewind: Instruction.Rewind,
        column: Instruction.Column,
        open_read: Index, // Table Index
        result_row: Instruction.ResultRow,
        next: Instruction.Next,
        transaction: Instruction.Transaction,
        string: Instruction.String,
        integer: Instruction.Integer,

        fn opcode(inst: Instruction) Opcode {
            return switch (inst) {
                .init => .init,
                .halt => .halt,
                .eq => .eq,
                .neq => .neq,
                .goto => .goto,
                .row_id => .row_id,
                .rewind => .rewind,
                .column => .column,
                .open_read => .open_read,
                .result_row => .result_row,
                .next => .next,
                .transaction => .transaction,
                .string => .string,
                .integer => .integer,
            };
        }

        fn size(inst: Instruction) u32 {
            return switch (inst) {
                .halt => 0,
                .init, .goto, .open_read => 4,
                .eq, .neq => @sizeOf(Instruction.Equal),
                .row_id => @sizeOf(Instruction.RowId),
                .result_row => @sizeOf(Instruction.ResultRow),
                .rewind => @sizeOf(Instruction.Rewind),
                .column => @sizeOf(Instruction.Column),
                .next => @sizeOf(Instruction.Next),
                .transaction => @sizeOf(Instruction.Transaction),
                .string => @sizeOf(Instruction.String),
                .integer => @sizeOf(Instruction.Integer),
            };
        }

        const Equal = struct {
            lhs_reg: Register.Index,
            rhs_reg: Register.Index,
            jump: InstIndex,
        };

        // Store in register P2 an integer which is the key of the table entry that P1 is currently point to.
        // P1 can be either an ordinary table or a virtual table. There used to be a separate OP_VRowid opcode for use with virtual tables,
        // but this one opcode now works for both table types.
        const RowId = struct {
            read_cursor: Index,
            store_reg: Register.Index,
        };

        // The next use of the Rowid or Column or Next instruction for P1 will refer to the first entry in the database table or index.
        // If the table or index is empty, jump immediately to P2. If the table or index is not empty, fall through to the following instruction.
        // If P2 is zero, that is an assertion that the P1 table is never empty and hence the jump will never be taken.
        // This opcode leaves the cursor configured to move in forward order, from the beginning toward the end. In other words, the cursor is configured to use Next, not Prev.
        const Rewind = struct {
            table: Index,
            end_inst: InstIndex,
        };

        // Interpret the data that cursor P1 points to as a structure built using the MakeRecord instruction. Extract the P2-th column from this record.
        // If there are less than (P2+1) values in the record, extract a NULL.
        // The value extracted is stored in register P3.
        // If the record contains fewer than P2 fields, then extract a NULL. Or, if the P4 argument is a P4_MEM use the value of the P4 argument as the result.
        const Column = struct {
            cursor: Index,
            store_reg: Register.Index,
            col: Index,
        };

        // The registers P1 through P1+P2-1 contain a single row of results. This opcode causes the sqlite3_step() call to terminate with an SQLITE_ROW return code
        // and it sets up the sqlite3_stmt structure to provide access to the r(P1)..r(P1+P2-1) values as the result row.
        const ResultRow = struct {
            start_reg: Register.Index,
            end_reg: Register.Index,
        };

        const Next = struct {
            cursor: Index,
            success_jump: InstIndex,
        };

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
        const Transaction = struct {
            database_id: u32,
            write: bool,
            // TODO: transaction schema validation

            const Repr = struct {
                db_write: u32,

                pub fn unpack(self: Repr) Transaction {
                    return .{
                        .database_id = self.db_write >> 1,
                        .write = self.db_write & 1 == 1,
                    };
                }
            };

            pub fn pack(self: Transaction) Repr {
                var db_write = self.database_id << 1;
                db_write |= if (self.write) 1 else 0;
                return .{
                    .db_write = db_write,
                };
            }
        };

        const String = struct {
            string: NullTerminatedString,
            store_reg: Register.Index,
        };

        const Integer = struct {
            int: i64,
            store_reg: Register.Index,

            const Repr = struct {
                int_0: u32,
                int_1: u32,
                store_reg: Register.Index,

                pub fn unpack(self: Repr) Integer {
                    const packed_int: PackedU64 = .{ .a = self.int_0, .b = self.int_1 };
                    const unpack_int: i64 = @bitCast(packed_int.unwrap());
                    return .{
                        .int = unpack_int,
                        .store_reg = self.store_reg,
                    };
                }
            };

            pub fn pack(self: Integer) Repr {
                const packed_int = PackedU64.init(self.int);
                return .{
                    .store_reg = self.store_reg,
                    .int_0 = packed_int.a,
                    .int_1 = packed_int.b,
                };
            }
        };
    };

    const Condition = struct {
        equality: Condition.Equality,
        lhs: union(enum) {
            column: Index, // Column index
            condition: Index, // Condition index
        },
        rhs: union(enum) {
            condition: Index.Optional,
            string: NullTerminatedString,
            int: i64,
            float: f64,
        },

        const Equality = enum(u8) {
            @"or",
            @"and",
            eq,
            ne,
            lt,
            lte,
            gt,
            gte,
        };

        const Repr = struct {
            lhs: u32,
            rhs_0: u32,
            rhs_1: u32,
        };
    };

    const Cursor = struct {
        index: u32,
    };

    const Key = union(enum) {
        table: Table,
        column: Column,
        condition: Condition,
        cursor: Cursor,
    };

    pub fn dump(ip: *InternPool, index: Index.Optional) void {
        const buf: [512]u8 = undefined;
        var fbs = io.fixedBufferStream(@constCast(&buf));
        _ = ip.bufWrite(@constCast(&fbs), index) catch null;
        const slice = fbs.getWritten();
        print(slice.ptr, slice.len);
    }

    fn bufWrite(ip: *InternPool, buffer: *FixedBufferStream([]u8), index: Index.Optional) anyerror!void {
        if (index.unwrap() == null) {
            _ = try buffer.write("NULL");
            return;
        }
        const key: Key = ip.indexToKey(index.unwrap().?);
        switch (key) {
            .condition => |condition_data| {
                switch (condition_data.lhs) {
                    .column => |column| {
                        switch (condition_data.equality) {
                            .eq => _ = try buffer.write("(EQ "),
                            .ne => _ = try buffer.write("(NE "),
                            .lt => _ = try buffer.write("(LT "),
                            .lte => _ = try buffer.write("(LTE "),
                            .gt => _ = try buffer.write("(GT "),
                            .gte => _ = try buffer.write("(GTE "),
                            else => unreachable, // Not a column equality
                        }
                        switch (condition_data.rhs) {
                            .int => |int_value| try fmt.format(buffer.writer().any(), "COL_{d}, {d})", .{ @intFromEnum(column), int_value }),
                            .float => |float_value| try fmt.format(buffer.writer().any(), "COL_{d}, {e})", .{ @intFromEnum(column), float_value }),
                            .string => |str_value| try fmt.format(buffer.writer().any(), "COL_{d}, {s})", .{ @intFromEnum(column), str_value.slice(ip) }),
                            else => unreachable,
                        }
                    },
                    .condition => |condition_lhs| {
                        switch (condition_data.equality) {
                            .@"and" => _ = try buffer.write("(AND "),
                            .@"or" => _ = try buffer.write("(OR "),
                            else => unreachable, // Not a condition equality
                        }
                        switch (condition_data.rhs) {
                            .condition => |condition_rhs| {
                                try ip.bufWrite(buffer, condition_lhs.toOptional());
                                _ = try buffer.write(", ");
                                try ip.bufWrite(buffer, condition_rhs);
                                _ = try buffer.write(")");
                            },
                            else => unreachable, // Can only compare condition to another condition
                        }
                    },
                }
            },
            else => unreachable, // TODO: implement dump for other key types
        }
    }

    fn addExtra(ip: *InternPool, alloc: Allocator, item: anytype) Allocator.Error!u32 {
        const len = ip.extra.items.len;
        // Each data index in extra is 4 bytes. So we bit shift to the right by 2 (4 bytes) to determine how many 32 bit (4 byte) extra indices we need.
        const size: u32 = @sizeOf(@TypeOf(item)) >> 2;
        try ip.extra.appendNTimes(alloc, 0, size);
        ip.insertExtra(len, item);
        return len;
    }

    fn insertExtra(ip: *InternPool, index: u32, item: anytype) void {
        // const fields = @typeInfo(@TypeOf(item)).@"struct".fields;
        const fields = @typeInfo(@TypeOf(item)).Struct.fields;
        inline for (fields, 0..) |field, i| {
            ip.extra.items[index + i] = switch (field.type) {
                Index, Index.Optional, Register.Index, InstIndex, NullTerminatedString, String => @intFromEnum(@field(item, field.name)),
                u32,
                => @bitCast(@field(item, field.name)),
                else => @compileError("bad field type: " ++ @typeName(field.type)),
            };
        }
    }

    fn extraData(ip: *InternPool, comptime T: type, index: u32) T {
        const extra_items = ip.extra.items;
        var result: T = undefined;

        // const fields = @typeInfo(T).@"struct".fields;
        const fields = @typeInfo(T).Struct.fields;
        inline for (fields, index..) |field, extra_index| {
            const extra_item = extra_items[extra_index];
            @field(result, field.name) = switch (field.type) {
                Index,
                Index.Optional,
                InstIndex,
                Register.Index,
                String,
                NullTerminatedString,
                => @enumFromInt(extra_item),
                u32 => @bitCast(extra_item),
                else => @compileError("bad field type: " ++ @typeName(field.type)),
            };
        }

        return result;
    }

    fn extraSize(item: Item) u32 {
        switch (item.tag) {
            .condition_or,
            .condition_and,
            .condition_lte_int,
            .condition_lte_float,
            .condition_lt_int,
            .condition_lt_float,
            .condition_gt_int,
            .condition_gt_float,
            .condition_gte_int,
            .condition_gte_float,
            .condition_eq_int,
            .condition_eq_float,
            .condition_eq_string,
            .condition_ne_int,
            .condition_ne_float,
            .condition_ne_string,
            => {
                return @sizeOf(Condition.Repr);
            },
            .table => {
                return @sizeOf(Table.Repr);
            },
            .column => {
                return @sizeOf(Column.Repr);
            },
            .cursor => {
                return @sizeOf(Cursor);
            },
        }
    }

    fn itemPlaceAt(ip: *InternPool, index: u32, item: Item) void {
        const len: u32 = ip.items.len;
        if (len == index) {
            return ip.items.appendAssumeCapacity(item);
        } else {
            ip.items.set(index, item);
        }
    }

    fn extraPlaceAt(ip: *InternPool, alloc: Allocator, item: Item, data: anytype) Allocator.Error!u32 {
        // TODO: see if I can fix this comptime assert
        // comptime assert(@sizeOf(@TypeOf(data)) == InternPool.extraSize(item));
        const len: u32 = ip.extra.items.len;
        const index = item.data;
        if (len == index) {
            return try ip.addExtra(alloc, data);
        } else {
            ip.insertExtra(index, data);
            return index;
        }
    }

    pub fn put(ip: *InternPool, alloc: Allocator, key: Key) Allocator.Error!Index {
        const index: u32 = ip.items.len;
        return try ip.putAtIndex(alloc, key, index);
    }

    pub fn update(ip: *InternPool, alloc: Allocator, index: Index, updated_key: Key) Allocator.Error!void {
        _ = try ip.putAtIndex(alloc, updated_key, @intFromEnum(index));
    }

    // TODO: figure out if this needs to be a getOrPut. Then we need to refactor to use a hashmap with they keys instead of a simple array
    fn putAtIndex(ip: *InternPool, alloc: Allocator, key: Key, index: u32) Allocator.Error!Index {
        const len = ip.items.len;
        const extra_len = ip.extra.items.len;
        const end = len == index;
        var item: ?Item = if (end) null else ip.items.get(index);
        try ip.items.ensureUnusedCapacity(alloc, 1);
        switch (key) {
            .condition => {
                const cond = key.condition;
                const lhs: u32 = switch (cond.lhs) {
                    .condition, .column => |col_cond| @intFromEnum(col_cond),
                };
                const rhs: PackedU64 = switch (cond.rhs) {
                    .string => |cond_string| .{ .a = @intFromEnum(cond_string), .b = 0 },
                    .int => |cond_int| PackedU64.init(cond_int),
                    .float => |cond_float| PackedU64.init(cond_float),
                    .condition => |cond_index| .{ .a = @intFromEnum(cond_index), .b = 0 },
                };
                const tag: Tag = switch (cond.equality) {
                    .eq => switch (cond.rhs) {
                        .string => .condition_eq_string,
                        .int => .condition_eq_int,
                        .float => .condition_eq_float,
                        .condition => unreachable,
                    },
                    .ne => switch (cond.rhs) {
                        .string => .condition_ne_string,
                        .int => .condition_eq_int,
                        .float => .condition_eq_float,
                        .condition => unreachable,
                    },
                    .lt => switch (cond.rhs) {
                        .int => .condition_lt_int,
                        .float => .condition_lt_float,
                        else => unreachable,
                    },
                    .lte => switch (cond.rhs) {
                        .int => .condition_lte_int,
                        .float => .condition_lte_float,
                        else => unreachable,
                    },
                    .gt => switch (cond.rhs) {
                        .int => .condition_gt_int,
                        .float => .condition_gt_float,
                        else => unreachable,
                    },
                    .gte => switch (cond.rhs) {
                        .int => .condition_gte_int,
                        .float => .condition_gte_float,
                        else => unreachable,
                    },
                    .@"or" => .condition_or,
                    .@"and" => .condition_and,
                };
                if (item == null) {
                    item = .{ .tag = tag, .data = extra_len };
                }
                _ = try ip.extraPlaceAt(alloc, item.?, Condition.Repr{
                    .lhs = lhs,
                    .rhs_0 = rhs.a,
                    .rhs_1 = rhs.b,
                });
                ip.itemPlaceAt(index, item.?);
            },
            .column => {
                const col = key.column;
                const flags: Column.Flags = .{ .tag = @intFromEnum(col.tag), .is_primary_key = col.is_primary_key, .id = @truncate(col.id) };
                if (item == null) {
                    item = .{ .tag = .column, .data = extra_len };
                }
                _ = try ip.extraPlaceAt(alloc, item.?, Column.Repr{
                    .name = col.name,
                    .next_column = col.next_column,
                    .flags = @bitCast(flags),
                });
                ip.itemPlaceAt(index, item.?);
            },
            .table => {
                const tbl = key.table;
                if (item == null) {
                    item = .{ .tag = .table, .data = extra_len };
                }
                _ = try ip.extraPlaceAt(alloc, item.?, Table.Repr{
                    .name = tbl.name,
                    .page = tbl.page,
                    .first_column = tbl.first_column,
                });
                ip.itemPlaceAt(index, item.?);
            },
            .cursor => {
                const cursor = key.cursor;
                item = .{ .tag = .cursor, .data = cursor.index };
                ip.itemPlaceAt(index, item.?);
            },
        }
        return @enumFromInt(index);
    }

    pub fn indexToKey(ip: *InternPool, index: Index) Key {
        debug("indexToKey: {d} len: {d}", .{ @intFromEnum(index), ip.items.len });
        const item = ip.items.get(@intFromEnum(index));
        switch (item.tag) {
            .condition_or,
            .condition_and,
            .condition_lte_int,
            .condition_lte_float,
            .condition_lt_int,
            .condition_lt_float,
            .condition_gt_int,
            .condition_gt_float,
            .condition_gte_int,
            .condition_gte_float,
            .condition_eq_int,
            .condition_eq_float,
            .condition_eq_string,
            .condition_ne_int,
            .condition_ne_float,
            .condition_ne_string,
            => {
                const extra_data: Condition.Repr = ip.extraData(Condition.Repr, item.data);
                const lhs_index: Index = @enumFromInt(extra_data.lhs);
                const rhs: PackedU64 = .{ .a = extra_data.rhs_0, .b = extra_data.rhs_1 };
                const result: Condition = switch (item.tag) {
                    .condition_or => .{ .equality = .@"or", .lhs = .{ .condition = lhs_index }, .rhs = .{ .condition = @enumFromInt(rhs.a) } },
                    .condition_and => .{ .equality = .@"and", .lhs = .{ .condition = lhs_index }, .rhs = .{ .condition = @enumFromInt(rhs.a) } },
                    .condition_lte_int => .{ .equality = .lte, .lhs = .{ .column = lhs_index }, .rhs = .{ .int = @bitCast(rhs) } },
                    .condition_lt_int => .{ .equality = .lt, .lhs = .{ .column = lhs_index }, .rhs = .{ .int = @bitCast(rhs) } },
                    .condition_gte_int => .{ .equality = .gte, .lhs = .{ .column = lhs_index }, .rhs = .{ .int = @bitCast(rhs) } },
                    .condition_gt_int => .{ .equality = .gt, .lhs = .{ .column = lhs_index }, .rhs = .{ .int = @bitCast(rhs) } },
                    .condition_eq_int => .{ .equality = .eq, .lhs = .{ .column = lhs_index }, .rhs = .{ .int = @bitCast(rhs) } },
                    .condition_ne_int => .{ .equality = .ne, .lhs = .{ .column = lhs_index }, .rhs = .{ .int = @bitCast(rhs) } },
                    .condition_lte_float => .{ .equality = .lte, .lhs = .{ .column = lhs_index }, .rhs = .{ .float = @bitCast(rhs) } },
                    .condition_lt_float => .{ .equality = .lt, .lhs = .{ .column = lhs_index }, .rhs = .{ .float = @bitCast(rhs) } },
                    .condition_gte_float => .{ .equality = .gte, .lhs = .{ .column = lhs_index }, .rhs = .{ .float = @bitCast(rhs) } },
                    .condition_gt_float => .{ .equality = .gt, .lhs = .{ .column = lhs_index }, .rhs = .{ .float = @bitCast(rhs) } },
                    .condition_eq_float => .{ .equality = .eq, .lhs = .{ .column = lhs_index }, .rhs = .{ .float = @bitCast(rhs) } },
                    .condition_ne_float => .{ .equality = .ne, .lhs = .{ .column = lhs_index }, .rhs = .{ .float = @bitCast(rhs) } },
                    .condition_eq_string => .{ .equality = .eq, .lhs = .{ .column = lhs_index }, .rhs = .{ .string = @enumFromInt(rhs.a) } },
                    .condition_ne_string => .{ .equality = .ne, .lhs = .{ .column = lhs_index }, .rhs = .{ .string = @enumFromInt(rhs.a) } },
                    else => unreachable, // Only handling conditions
                };
                return .{ .condition = result };
            },
            .column => {
                const extra_data = ip.extraData(Column.Repr, item.data);
                const flags: Column.Flags = @bitCast(extra_data.flags);
                const result: Column = .{
                    .name = extra_data.name,
                    .next_column = extra_data.next_column,
                    .tag = @enumFromInt(flags.tag),
                    .id = flags.id,
                    .is_primary_key = flags.is_primary_key,
                };
                return .{ .column = result };
            },
            .table => {
                const extra_data = ip.extraData(Table.Repr, item.data);
                const result: Table = .{ .name = extra_data.name, .page = extra_data.page, .first_column = extra_data.first_column };
                return .{ .table = result };
            },
            .cursor => {
                const result: Cursor = .{ .index = item.data };
                return .{ .cursor = result };
            },
        }
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

// TODO: replace with internpool key
const SelectStmt = struct {
    columns: u64, // Each bit represents one column in the table TODO: support tables with more than 64 columns
    table: InternPool.Index, // table index
    where: InternPool.Index.Optional, // Optional condition index
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
    sql: InternPool.NullTerminatedString,
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
        return .{
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

    pub fn getTable(self: *Db, alloc: Allocator, table_name: []const u8, ip: *InternPool) Error!SQLiteDbTable {
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
                            const sql_str = try InternPool.NullTerminatedString.initAddSentinel(alloc, sql_col.text, ip);
                            return .{
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
    ip: *InternPool,
    token_list: *TokenList,
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

    pub fn init(
        gpa: Allocator,
        token_list: *TokenList,
        intern_pool: *InternPool,
        source: [:0]u8,
        db: Db,
    ) Error!ASTGen {
        return ASTGen{
            .index = 0,
            .gpa = gpa,
            .token_list = token_list,
            .ip = intern_pool,
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

    fn buildCreateTable(self: *ASTGen, sqlite_table: SQLiteDbTable) Error!InternPool.Index {
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
        var tokenizer = Tokenizer.from(sql_str.slice(self.ip), 0);
        try tokenizer.ingest(self.gpa, self.token_list);

        var state: State = .create;
        var name: ?InternPool.NullTerminatedString = null;
        var tag: ?InternPool.Column.Tag = null;
        var primary_key: PrimaryKeyState = PrimaryKeyState.unfilled;
        var col_count: u32 = 0;
        var col_index: ?InternPool.Index = null;
        var table_index: ?InternPool.Index = null;

        // TODO: errdefer dealloc elements of partially allocated table

        while (index < self.token_list.len) : (index += 1) {
            const token: MinimizedToken = self.token_list.get(index);
            debug("buildCreateTable token: {}", .{token});
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
                            const token_end = ASTGen.getTokenEnd(sql_str.slice(self.ip), token);
                            const table_name = try sql_str.toString().copySubstringNullTerminate(self.gpa, token.start, token_end, self.ip);
                            debug("table_name: {s}", .{table_name.slice(self.ip)});
                            table_index = try self.ip.put(self.gpa, .{
                                .table = .{
                                    .name = table_name,
                                    .page = sqlite_table.page - 1, // TODO: see if -1 can be removed
                                    .first_column = InternPool.Index.Optional.none,
                                },
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
                            const token_end = ASTGen.getTokenEnd(sql_str.slice(self.ip), token);
                            name = try sql_str.toString().copySubstringNullTerminate(self.gpa, token.start, token_end, self.ip);
                            state = .table_col_type;
                        },
                        else => return Error.InvalidSyntax,
                    }
                },
                .table_col_type => {
                    tag = switch (token.tag) {
                        .keyword_integer => .integer,
                        .keyword_text => .text,
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
                            const new_index = try self.ip.put(self.gpa, .{ .column = .{
                                .name = name.?,
                                .next_column = InternPool.Index.Optional.none,
                                .id = col_count,
                                .tag = tag.?,
                                .is_primary_key = primary_key == PrimaryKeyState.current,
                            } });
                            col_count += 1;
                            if (col_index == null) {
                                var data = self.ip.indexToKey(table_index.?);
                                data.table.first_column = new_index.toOptional();
                                try self.ip.update(self.gpa, table_index.?, data);
                            } else {
                                var data = self.ip.indexToKey(col_index.?);
                                data.column.next_column = new_index.toOptional();
                                try self.ip.update(self.gpa, col_index.?, data);
                            }
                            col_index = new_index;
                            if (primary_key == PrimaryKeyState.current) {
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
        var table: ?InternPool.Index = null;
        var column_list_index: u32 = maxInt(u32);
        var processed_columns: bool = false;
        var where: InternPool.Index.Optional = InternPool.Index.Optional.none;
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
                                const is_col = self.ip.columnFromName(tbl, col_name);
                                if (is_col) |col_result| {
                                    columns |= (@as(u64, 1) << @truncate(col_result.count));
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
                                const sqlite_table = try self.db.getTable(self.gpa, table_name, self.ip);
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
                            self.ip.dump(where);
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

        return .{
            .columns = columns,
            .table = table.?,
            .where = where,
        };
    }

    pub fn buildWhereClause(self: *ASTGen, table: InternPool.Index) Error!InternPool.Index.Optional {
        var state: State = .where;
        var equality: ?TokenType = null;
        var col_index: InternPool.Index.Optional = InternPool.Index.Optional.none;
        var last_element_andor = false;
        var expr_index: InternPool.Index.Optional = InternPool.Index.Optional.none;
        var expr_prev_index: InternPool.Index.Optional = InternPool.Index.Optional.none;
        var expr_first_index: InternPool.Index.Optional = InternPool.Index.Optional.none;
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
                        const col_optional = self.ip.columnFromName(table, column_name);
                        if (col_optional) |col| {
                            col_index = col.index.toOptional();
                        } else {
                            break;
                        }
                        state = .where_equality;
                    },
                    .keyword_and, .keyword_or => {
                        if (last_element_andor or expr_index.unwrap() == null) {
                            break;
                        }
                        const replace_first_expr = expr_first_index == expr_index;
                        const expr_prev_temp_index = expr_index;
                        const new_index = try self.ip.put(self.gpa, .{
                            .condition = .{
                                .lhs = .{ .condition = expr_index.unwrap().? },
                                .equality = switch (token.tag) {
                                    .keyword_and => .@"and",
                                    .keyword_or => .@"or",
                                    else => unreachable, // and or conditions
                                },
                                .rhs = .{ .condition = InternPool.Index.Optional.none },
                            },
                        });
                        expr_index = new_index.toOptional();
                        last_element_andor = true;
                        if (expr_prev_index.unwrap()) |expr| {
                            var key = self.ip.indexToKey(expr);
                            key.condition.rhs = .{ .condition = expr_index };
                            try self.ip.update(self.gpa, expr, key);
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
                        if (expr_first_index.unwrap()) |index| {
                            return index.toOptional();
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
                    debug("where_rhs eq: {?}, col_index: {d}", .{ equality, @intFromEnum(col_index) });
                    if (equality == null or col_index.unwrap() == null) {
                        debug("where_rhs missing", .{});
                        return Error.InvalidSyntax;
                    }
                    switch (token.tag) {
                        .double_quote_word => {
                            const string_literal = ASTGen.getTokenSource(self.source, token);
                            debug("where_rhs literal: {s}", .{string_literal});
                            const value = try InternPool.NullTerminatedString.initAddSentinel(self.gpa, string_literal[1 .. string_literal.len - 1], self.ip);
                            expr_prev_index = expr_index;
                            const new_index = try self.ip.put(self.gpa, .{
                                .condition = .{
                                    .lhs = .{ .column = col_index.unwrap().? },
                                    .equality = switch (equality.?) {
                                        .eq => .eq,
                                        .ne => .ne,
                                        else => return Error.InvalidSyntax,
                                    },
                                    .rhs = .{ .string = value },
                                },
                            });
                            expr_index = new_index.toOptional();
                        },
                        .integer => {
                            const slice = ASTGen.getTokenSource(self.source, token);
                            const value = fmt.parseInt(i64, slice, 10) catch break;
                            expr_prev_index = expr_index;
                            const new_index = try self.ip.put(self.gpa, .{
                                .condition = .{
                                    .lhs = .{ .column = col_index.unwrap().? },
                                    .equality = switch (equality.?) {
                                        .eq => .eq,
                                        .ne => .ne,
                                        else => return Error.InvalidSyntax,
                                    },
                                    .rhs = .{ .int = value },
                                },
                            });
                            expr_index = new_index.toOptional();
                        },
                        else => break,
                    }
                    last_element_andor = false;
                    if (expr_prev_index.unwrap()) |expr| {
                        var key = self.ip.indexToKey(expr);
                        key.condition.rhs = .{ .condition = expr_index.unwrap().?.toOptional() };
                        try self.ip.update(self.gpa, expr, key);
                    } else {
                        expr_first_index = expr_index;
                    }
                    equality = null;
                    col_index = InternPool.Index.Optional.none;
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
                    debug("built statement: select({d}, {d})", .{ select.columns, select.table });
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
    ip: *InternPool,
    table: InternPool.Table,
    index: InternPool.Index.Optional,

    pub fn from(intern_pool: *InternPool, table_index: InternPool.Index) TableMetadataReader {
        const table = intern_pool.indexToKey(table_index).table;
        return .{
            .ip = intern_pool,
            .table = table,
            .index = table.first_column,
        };
    }

    pub fn next(self: *TableMetadataReader) ?struct { col: InternPool.Column, index: InternPool.Index } {
        const result_index_opt = self.index.unwrap();
        if (result_index_opt) |result_index| {
            const element = self.ip.indexToKey(result_index).column;
            self.index = element.next_column;
            return .{ .col = element, .index = result_index };
        }
        return null;
    }
};

const ConditionTraversal = struct {
    ip: *InternPool,
    index: InternPool.Index.Optional,
    current_condition: InternPool.Condition.Equality,
    stack: ArrayListUnmanaged(InternPool.Index.Optional),
    last_pop: InternPool.Index.Optional,

    pub fn init(intern_pool: *InternPool, index: InternPool.Index) ConditionTraversal {
        return .{
            .ip = intern_pool,
            .index = index.toOptional(),
            .current_condition = .@"or",
            .stack = .{},
            .last_pop = InternPool.Index.Optional.none,
        };
    }

    pub fn next(self: *ConditionTraversal, alloc: Allocator) Allocator.Error!?InternPool.Condition {
        debug("next condition: {d}", .{self.index});
        while (true) {
            if (self.index.unwrap() != null) {
                const cond: InternPool.Condition = self.ip.indexToKey(self.index.unwrap().?).condition;
                switch (cond.equality) {
                    .@"or", .@"and" => {
                        try self.stack.append(alloc, self.index);
                        self.index = cond.lhs.condition.toOptional();
                        self.current_condition = cond.equality;
                    },
                    .eq, .ne => {
                        self.index = InternPool.Index.Optional.none;
                        return cond;
                    },
                    else => unreachable, // TODO: lt/gt
                }
            } else {
                if (self.stack.items.len == 0) return null;
                self.last_pop = self.stack.pop();
                debug("last pop: {d}", .{self.last_pop.unwrap().?});
                self.index = self.last_pop;
                if (self.last_pop.unwrap()) |pop| {
                    const key = self.ip.indexToKey(pop).condition;
                    self.index = key.rhs.condition;
                }
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
    ip: *InternPool,
    statement: Stmt,
    db: Db,

    pub fn init(
        gpa: Allocator,
        intern_pool: *InternPool,
        db: Db,
        statement: Stmt,
    ) Error!InstGen {
        return InstGen{
            .gpa = gpa,
            .ip = intern_pool,
            .statement = statement,
            .db = db,
        };
    }

    fn eqReplaceJump(self: *InstGen, index: InternPool.InstIndex, jump_address: InternPool.InstIndex) void {
        var inst = self.ip.getInst(index).?;
        switch (inst) {
            .eq => {
                inst.eq.jump = jump_address;
            },
            .neq => {
                inst.neq.jump = jump_address;
            },
            else => unreachable, // Replace jump only on eq instructions
        }
        self.ip.setInst(index, inst);
    }

    fn eqNegate(self: *InstGen, index: InternPool.InstIndex) void {
        const old_inst = self.ip.getInst(index).?;
        const new_inst: InternPool.Instruction = switch (old_inst) {
            .eq => |data| .{ .neq = data },
            .neq => |data| .{ .eq = data },
            else => unreachable, // Can only negate eq/ne opcodes
        };
        self.ip.setInst(index, new_inst);
    }

    fn addInst(self: *InstGen, key: InternPool.Instruction) Allocator.Error!InternPool.InstIndex {
        return try self.ip.addInst(self.gpa, key);
    }

    pub fn buildInstructions(self: *InstGen) Error!void {
        switch (self.statement) {
            Stmt.select => {
                const select = self.statement.select;
                const table = self.ip.indexToKey(select.table).table;
                // const page_index: u32 = select.table.page - 1;
                debug("page_index: {d}", .{table.page});

                const cursor = try self.ip.put(self.gpa, .{ .cursor = .{ .index = 0 } });

                const init_index = try self.addInst(.{ .init = InternPool.InstIndex.none });
                // const init_index = try self.markInst(.init);
                const open_read_index = try self.addInst(.{ .open_read = select.table });
                // const open_read_index = try self.markInst(.open_read);
                const rewind_index = try self.addInst(.{ .rewind = .{ .table = select.table, .end_inst = InternPool.InstIndex.none } });
                // const rewind_index = try self.markInst(.rewind);
                const rewind_start = self.ip.peekInst();

                var reg_count = Register.Index.first;
                var reader = TableMetadataReader.from(self.ip, select.table);
                const where_clause = select.where;
                const compare_reg = reg_count;
                // const compare_reg = try self.ip.put(self.gpa, .{ .register = InternPool.Register.none });
                var final_comparison: InternPool.InstIndex = InternPool.InstIndex.none;
                if (where_clause.unwrap()) |ref| {
                    var traversal = ConditionTraversal.init(self.ip, ref);
                    defer traversal.deint(self.gpa);
                    var comparisons: ArrayListUnmanaged(InternPool.InstIndex) = .{};
                    defer comparisons.deinit(self.gpa);
                    var columns_start = self.ip.peekInst();
                    while (try traversal.next(self.gpa)) |cond| {
                        _ = try self.addInst(.{ .column = .{
                            .cursor = cursor,
                            .store_reg = compare_reg,
                            .col = cond.lhs.column,
                        } });
                        reg_count = reg_count.increment();
                        switch (traversal.current_condition) {
                            .@"or" => {
                                try comparisons.append(self.gpa, self.ip.peekInst());
                                // TODO: add other conditions (lt/lte/gt/gte)
                                if (cond.equality == .eq) {
                                    _ = try self.addInst(.{ .eq = .{
                                        .lhs_reg = compare_reg,
                                        .rhs_reg = reg_count,
                                        .jump = InternPool.InstIndex.none,
                                    } });
                                } else {
                                    _ = try self.addInst(.{ .neq = .{
                                        .lhs_reg = compare_reg,
                                        .rhs_reg = reg_count,
                                        .jump = InternPool.InstIndex.none,
                                    } });
                                }
                            },
                            else => return Error.InvalidSyntax, // TODO: implement and clause
                        }
                    } else {
                        columns_start = self.ip.peekInst();
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

                var output_count = reg_count.increment();
                var col_count: u32 = 0;
                while (reader.next()) |col_result| {
                    const col = col_result.col;
                    const col_i = col_result.index;
                    // TODO: support more than 64 columns
                    if (select.columns & (@as(u64, 0x1) << @truncate(col_count)) > 0) {
                        if (col.is_primary_key and col.tag == .integer) {
                            // rowId reads for a integer primary key row. If this isn't explicitly noted as a primary key,
                            // then column instruction is used instead.
                            _ = try self.addInst(.{ .row_id = .{
                                .read_cursor = cursor,
                                .store_reg = output_count,
                            } });
                            // try self.rowId(cursor, output_count);
                        } else {
                            _ = try self.addInst(.{ .column = .{
                                .cursor = cursor,
                                .store_reg = output_count,
                                .col = col_i,
                            } });
                            // try self.column(cursor, output_count, col_count);
                        }
                        output_count = output_count.increment();
                    }
                    col_count += 1;
                }
                debug("columns: {b}", .{select.columns});

                debug("output count: {d}", .{output_count});
                _ = try self.addInst(.{ .result_row = .{
                    .start_reg = reg_count,
                    .end_reg = output_count.increment(),
                } });
                // try self.resultRow(reg_count, output_count.increment());
                const next_index = try self.addInst(.{ .next = .{ .cursor = cursor, .success_jump = rewind_start } });
                // try self.next(cursor, rewind_start);
                const halt_index = try self.addInst(InternPool.Instruction.halt);
                // try self.halt();
                // TODO: support multiples databases, writing to tables
                const transaction_index = try self.addInst(.{ .transaction = .{ .database_id = 0, .write = false } });
                // try self.transaction(0, false);
                if (where_clause.unwrap()) |where| {
                    self.eqReplaceJump(final_comparison, next_index);
                    var traversal = ConditionTraversal.init(self.ip, where);
                    var store_reg = compare_reg.increment();
                    defer traversal.deint(self.gpa);
                    while (try traversal.next(self.gpa)) |cond| {
                        switch (cond.rhs) {
                            // .string => try self.string(cond.rhs.string, store_reg),
                            .string => _ = try self.addInst(.{ .string = .{ .string = cond.rhs.string, .store_reg = store_reg } }),
                            // .int => try self.integer(cond.rhs.int, store_reg),
                            .int => _ = try self.addInst(.{ .integer = .{ .int = cond.rhs.int, .store_reg = store_reg } }),
                            else => return Error.InvalidSyntax, // TODO: implement float
                        }
                        store_reg = store_reg.increment();
                    }
                }
                _ = try self.addInst(.{ .goto = open_read_index });
                // try self.goto(open_read_index);
                self.ip.setInst(init_index, .{ .init = transaction_index });
                // self.instInit(init_index, transaction_index);
                // self.openRead(open_read_index, page_index);
                self.ip.setInst(rewind_index, .{ .rewind = .{ .table = select.table, .end_inst = halt_index } });
                // self.rewind(rewind_index, halt_index);
                debug("instructions written", .{});
            },
        }
    }
};

// All registers are the same size, so its possible to update register type without allocating more data
const Register = union(enum) {
    none,
    int: i64,
    float: f64,
    string: StringLen,
    str: []u8, // TODO: consider removing these, and make all bytes be interned. Or use a 32 bit index instead of a pointer
    binary: []u8,

    const StringLen = struct {
        string: InternPool.String,
        len: u32,
    };

    const Index = enum(u32) {
        none = std.math.maxInt(u32),
        first = 0,
        _,

        pub fn unwrap(self: Index) ?u32 {
            switch (self) {
                .none => return null,
                else => return @intFromEnum(self),
            }
        }

        pub fn increment(self: Index) Index {
            return switch (self) {
                .none => @enumFromInt(0),
                else => @enumFromInt(@intFromEnum(self) + 1),
            };
        }
    };

    const Tag = enum(u8) {
        none,
        int,
        float,
        string,
        str,
        binary,
    };

    const Item = struct {
        tag: Tag,
        data: Repr,
    };

    const Repr = extern struct {
        @"0": u32,
        @"1": u32,
    };

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

    pub fn tag(self: Register) enum { none, int, float, str, string, binary } {
        return switch (self) {
            .none => .none,
            .int => .int,
            .float => .float,
            .str => .str,
            .string => .string,
            .binary => .binary,
        };
    }

    pub fn compare(self: Register, other: Register, ip: *InternPool) bool {
        if (self.tag() == other.tag()) {
            return switch (self) {
                .none => true,
                .int => self.int == other.int,
                .float => self.float == other.float,
                .str => eql(u8, self.str, other.str),
                .string => eql(u8, self.string.string.slice(self.string.len, ip), other.string.string.slice(self.string.len, ip)),
                .binary => unreachable, // TODO: implement
            };
        } else if (self.tag() == .str and other.tag() == .string) {
            return eql(u8, self.string.string.slice(self.string.len, ip), other.str);
        } else if (self.tag() == .string and other.tag() == .str) {
            return eql(u8, self.str, self.string.string.slice(self.string.len, ip));
        }
        return false;
    }

    pub fn toStr(self: Register, buffer: []u8, ip: *InternPool) anyerror![]u8 {
        return switch (self) {
            .none => try fmt.bufPrint(buffer, "[null]", .{}),
            .int => try fmt.bufPrint(buffer, "{d}", .{self.int}),
            .float => try fmt.bufPrint(buffer, "{e}", .{self.float}),
            .str => try fmt.bufPrint(buffer, "{s}", .{self.str}),
            .string => try fmt.bufPrint(buffer, "{s}", .{self.string.string.slice(self.string.len, ip)}),
            .binary => try fmt.bufPrint(buffer, "[binary]", .{}),
        };
    }

    pub fn toBuf(self: Register, buffer: []u8, ip: *InternPool) anyerror![]u8 {
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
                const fmt_slice = try fmt.bufPrint(buffer[8..], "{s}", .{self.string.string.slice(self.string.len, ip)});
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

const Vm = struct {
    gpa: Allocator,
    db: Db,
    ip: *InternPool,
    reg_list: MultiArrayList(Register.Item),
    pc: InternPool.InstIndex,

    const Cursor = struct {
        addr: u16,
        index: u32,
    };

    pub fn init(gpa: Allocator, db: Db, intern_pool: *InternPool) Vm {
        return .{
            .gpa = gpa,
            .db = db,
            .ip = intern_pool,
            .reg_list = .{},
            .pc = @enumFromInt(0),
        };
    }

    fn reg(self: *Vm, index: Register.Index) Register {
        const index_num = index.unwrap();
        if (index_num == null or index_num.? >= self.reg_list.len) {
            debug("reg: invalid index: {}", .{index});
            return Register.none;
        }
        const item = self.reg_list.get(@intFromEnum(index));
        const extra_data = item.data;
        return switch (item.tag) {
            .string => .{ .string = .{ .string = @enumFromInt(extra_data.@"0"), .len = extra_data.@"1" } },
            .str => .{ .str = @as([*]u8, @ptrFromInt(extra_data.@"0"))[0..(extra_data.@"1")] },
            .binary => .{ .binary = @as([*]u8, @ptrFromInt(extra_data.@"0"))[0..(extra_data.@"1")] },
            .int => .{ .int = @bitCast(PackedU64.init(extra_data).unwrap()) },
            .float => .{ .float = @bitCast(PackedU64.init(extra_data).unwrap()) },
            .none => Register.none,
        };
    }

    fn updateReg(self: *Vm, index: Register.Index, register: Register) Error!void {
        debug("reg index: {d}, len: {d}", .{ index, self.reg_list.len });
        // registers start at 1, not 0
        const pack: PackedU64 = switch (register) {
            .int => |reg_int| PackedU64.init(reg_int),
            .float => |reg_float| PackedU64.init(reg_float),
            .string => |reg_string| PackedU64{ .a = @intFromEnum(reg_string.string), .b = reg_string.len },
            .none => PackedU64{ .a = 0, .b = 0 },
            .str => |reg_str| PackedU64{
                .a = @intFromPtr(reg_str.ptr),
                .b = @bitCast(reg_str.len),
            },
            .binary => |reg_binary| PackedU64{
                .a = @intFromPtr(reg_binary.ptr),
                .b = @bitCast(reg_binary.len),
            },
        };
        const tag: Register.Tag = switch (register) {
            .int => .int,
            .float => .float,
            .str => .str,
            .string => .string,
            .binary => .binary,
            .none => .none,
        };
        const item: Register.Item = .{ .tag = tag, .data = .{ .@"0" = pack.a, .@"1" = pack.b } };

        const index_num = index.unwrap() orelse return Error.InvalidSyntax;

        if (index_num == self.reg_list.len) {
            try self.reg_list.append(self.gpa, item);
        } else {
            while (index_num >= self.reg_list.len) {
                try self.reg_list.append(self.gpa, .{ .tag = .none, .data = .{ .@"0" = 0, .@"1" = 0 } });
            }
            debug("updateReg: index_num: {d}, len: {d}", .{ index_num, self.reg_list.len });
            const slice = self.reg_list.slice();
            slice.items(.tag)[index_num] = item.tag;
            slice.items(.data)[index_num] = item.data;
        }
    }

    // TODO: do not reference instruction list or extra data directly. Have them go through a layer and provide a struct with field names.
    // That way don't have to figure out data.lhs/rhs for each instruction
    pub fn exec(self: *Vm) Error!void {
        var instruction: InternPool.Instruction = self.ip.getInst(self.pc).?;
        // TODO: multiple cursors
        // TODO: clean up these variables
        var buffer: ?[]u8 = null;
        var header: ?*SQLiteBtHeader = null;
        var record: ?SQLiteRecord = null;
        var col_count: u32 = 0;
        var cell_size: u32 = 0;
        var cell_count: u32 = 0;
        var col_value: ?SQLiteColumn = null;

        while (self.pc.unwrap() != null and instruction != InternPool.Instruction.halt) {
            const instruction_opt = self.ip.getInst(self.pc);
            if (instruction_opt) |inst| {
                debug("Inst {} at {}", .{ inst, self.pc });
                instruction = inst;
            } else {
                debug("uh, oh. null instruction at pc: {}", .{self.pc});
                return;
            }
            switch (instruction) {
                .init => |init_inst| {
                    debug("init inst: {}, inst count: {d}", .{ init_inst, self.ip.instructions.len });
                    self.pc = init_inst;
                },
                .open_read => |table_index| {
                    const table = self.ip.indexToKey(table_index).table;
                    debug("table: {}", .{table});

                    buffer = self.db.readPage(table.page);
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
                    self.pc = self.pc.increment();
                },
                .rewind => |rewind_data| {
                    const end_inst = rewind_data.end_inst;
                    if (record != null) {
                        col_value = record.?.next();
                        if (col_value == null) {
                            break;
                        }
                        col_count += 1;
                        self.pc = self.pc.increment();
                    } else {
                        debug("table is empty", .{});
                        self.pc = end_inst;
                    }
                },
                .row_id => |row_id_data| {
                    assert(record != null);
                    debug("row_id SQLiteColumn: {d}", .{record.?.row_id});
                    try self.updateReg(row_id_data.store_reg, Register{ .int = @intCast(record.?.row_id) });
                    self.pc = self.pc.increment();
                },
                .column => |column_data| {
                    assert(record != null);
                    const store_reg = column_data.store_reg;
                    const col_index = column_data.col;
                    const col = self.ip.indexToKey(col_index).column;
                    if (col_count > col.id) {
                        record.?.reset();
                        col_count = 0;
                    }
                    while (col_count < col.id) : (col_count += 1) {
                        record.?.consume();
                    }
                    col_value = record.?.next();
                    col_count += 1;
                    assert(col_value != null);
                    try self.updateReg(store_reg, Register.fromColumn(col_value.?));
                    col_value = record.?.next();
                    debug("col_value: {?}", .{col_value});
                    col_count += 1;
                    self.pc = self.pc.increment();
                },
                .result_row => |result_row_data| {
                    const start_reg = result_row_data.start_reg;
                    const end_reg = result_row_data.end_reg;
                    const end_reg_num = end_reg.unwrap().?;

                    // TODO: refactor this mess. Probably own struct for writing..
                    var i: u32 = @intFromEnum(start_reg);
                    const len: u32 = @intFromEnum(end_reg) - i;
                    var write_buf: [256]u8 = undefined;
                    var row_buf: [512]u8 = undefined;
                    var row_buf_written: u32 = 4;
                    var write_count: u8 = 0;
                    row_buf[0..4].* = std.mem.toBytes(len);
                    while (i < end_reg_num) : (i += 1) {
                        const cur_reg = self.reg(@enumFromInt(i));
                        const written = cur_reg.toStr(@constCast(write_buf[write_count..]), self.ip) catch write_buf[write_count..];
                        const written_row = cur_reg.toBuf(row_buf[row_buf_written..], self.ip) catch row_buf[row_buf_written..];
                        row_buf_written += written_row.len;
                        const written_len: u8 = @intCast(written.len);
                        debug("written len: {d}", .{written_len});
                        write_count += written_len;
                        if (i != end_reg_num - 1) {
                            write_buf[write_count] = '|';
                            write_count += 1;
                        }
                    }
                    print(write_buf[0..write_count].ptr, write_buf[0..write_count].len);
                    renderRow(row_buf[0..row_buf_written].ptr, row_buf[0..row_buf_written].len);
                    self.pc = self.pc.increment();
                },
                .neq, .eq => |eq_data| {
                    const jump_address = eq_data.jump;
                    const lhs_reg_index = eq_data.lhs_reg;
                    const rhs_reg_index = eq_data.rhs_reg;
                    const lhs_reg = self.reg(lhs_reg_index);
                    const rhs_reg = self.reg(rhs_reg_index);
                    const equal_values: bool = lhs_reg.compare(rhs_reg, self.ip);

                    const is_eq: bool = switch (instruction) {
                        .eq => true,
                        else => false,
                    };

                    if ((is_eq and equal_values) or (!is_eq and !equal_values)) {
                        self.pc = jump_address;
                        debug("jump: {d}", .{jump_address});
                    } else {
                        self.pc = self.pc.increment();
                    }
                },
                .string => |string_data| {
                    const store_reg = string_data.store_reg;
                    const str = string_data.string.toString();
                    const str_len = string_data.string.slice(self.ip).len;
                    try self.updateReg(store_reg, .{ .string = .{ .string = str, .len = @intCast(str_len) } });
                    self.pc = self.pc.increment();
                },
                .integer => |integer_data| {
                    const store_reg = integer_data.store_reg;
                    const int = integer_data.int;
                    try self.updateReg(store_reg, .{ .int = int });
                    self.pc = self.pc.increment();
                },
                .next => |next_data| {
                    debug("col_value: {?}", .{col_value});
                    if (cell_count >= cell_size - 1) {
                        self.pc = self.pc.increment();
                    } else {
                        cell_count += 1;

                        const addr = header.?.getCellAddr(buffer.?, cell_count);
                        debug("cell address: {x}", .{addr});
                        record = SQLiteRecord.from(buffer.?[addr..]);
                        col_value = record.?.next();

                        self.pc = next_data.success_jump;
                    }
                },
                .halt => break,
                .transaction => {
                    // TODO: support transactions, attached databases, writing
                    self.pc = self.pc.increment();
                },
                .goto => |goto_inst| {
                    self.pc = goto_inst;
                },
                // else => debug("instruction not implemented: {}", .{instruction.opcode}),
            }
        }
    }
};

const MinimizedToken = struct { tag: TokenType, start: u32 };

// TODO: put all these into a self-contained structure like how the Zig compiler does with InternPool
// Then only return the filled out structures, not the data oriented design ones
var extra: ArrayListUnmanaged(u32) = .{};
const TokenList = MultiArrayList(MinimizedToken);

fn parseStatement(str: [:0]u8, file_buffer: []u8) Error!void {
    var tokenizer = Tokenizer.from(str, 0);
    var fixed_alloc = heap.FixedBufferAllocator.init(&memory_buf);

    var tokens = TokenList{};
    defer tokens.deinit(fixed_alloc.allocator());

    var intern_pool = InternPool.init();

    try tokenizer.ingest(fixed_alloc.allocator(), &tokens);

    const db = try Db.from(file_buffer);

    // ASTGen can allocate more tokens, so we pass the struct instead of the underlying buffer
    var ast = try ASTGen.init(fixed_alloc.allocator(), &tokens, &intern_pool, str, db);
    const statement = try ast.buildStatement();
    debug("statement built!", .{});

    var inst_gen = try InstGen.init(fixed_alloc.allocator(), &intern_pool, db, .{ .select = statement });

    debug("building instructions", .{});
    try inst_gen.buildInstructions();
    debug("inst generated!", .{});

    var vm = Vm.init(fixed_alloc.allocator(), db, &intern_pool);
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
