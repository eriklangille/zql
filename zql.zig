const std = @import("std");
const config = @import("config");
const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const assert = std.debug.assert;
const eqlLenIgnoreCase = std.static_string_map.eqlAsciiIgnoreCase;
const FixedBufferStream = std.io.FixedBufferStream;
const fmt = std.fmt;
const MultiArrayList = std.MultiArrayList;
const StaticStringMap = std.StaticStringMapWithEql;

// (arrayPointer: i32, length: i32)
extern fn print(ptr: [*]const u8, len: usize) void;

extern fn readBuffer(ptr: [*]const u8, offset: usize, len: usize) void;

extern fn renderRow(ptr: [*]const u8, len: usize) void;

export fn malloc(size: usize) ?*u8 {
    const page_allocator = std.heap.page_allocator;
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

const PackedU32 = packed struct {
    a: u8,
    b: u8,
    c: u8,
    d: u8,

    pub fn unwrap(self: PackedU32) u32 {
        return @bitCast(self);
    }
};

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

// Inspired by intern_pool.zig in the Zig source code. This data structure contains "high-density" representation
// of the abstract syntax tree (AST) in the items array and the VM instructions generated from the AST.
// It also contains byte strings (string_bytes), that can be reference using the String and NullTerminatedString enums.
// Each item in the items array takes 5 bytes - 4 bytes data and 1 byte tag. If additional data is required, it is allocated
// to the extra data array, with the 4 byte main data being a reference to the extra data. Each extra array item is also 4 bytes.
// The instruction array is the same as the items array, but for VM instructions instead of the AST.
// The objective of this interface is to use the fewest bytes possible. This is accomplished in a couple ways:
//   1. References to items in the InternPool are 4 byte integers (wrapped in an enum) instead of pointers or slices
//   2. Any external struct (called a "Key") is mapped to an internal representation that fits the in the smallest amount of bytes.
// A reference to that "Key" is called an "Index". The internal data can be retreived using the "indexToKey" function and a "Key" is
// stored as the intern representation with the "put" function.
// Items in the InternPool can updated using the "update" function, but the replacement value must take the same amount of bytes
// as the value being replaced. A common pattern in the code is to first add an item with a null reference, and then update that item
// once the real reference has been created later in the code.
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
        argument_column,
        argument_expression,
        argument_float,
        argument_int,
        argument_string,
        column,
        cursor,
        expression,
        expression_big,
        function,
        result_column,
        result_column_wildcard,
        root,
        table,
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
        function,
        @"if",
        if_not,
        gt,
        gte,
        lt,
        lte,
        add,
        subtract,
        multiply,
        divide,
        remainder,
        seek_gt,
        seek_ge,
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
            none = std.math.maxInt(u32),
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
            if (std.mem.eql(u8, col_key.name.slice(ip), col_name)) {
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

    pub fn markInst(ip: *InternPool, alloc: Allocator) Allocator.Error!InstIndex.Marked {
        const index: u32 = ip.instructions.len;
        try ip.instructions.append(alloc, .{ .opcode = .halt, .data = 0 });
        return @enumFromInt(index);
    }

    pub fn replaceInst(ip: *InternPool, alloc: Allocator, index: InstIndex.Marked, key: Instruction) Allocator.Error!InstIndex {
        return ip.allocInst(alloc, @intFromEnum(index), key);
    }

    pub fn addInst(ip: *InternPool, alloc: Allocator, key: Instruction) Allocator.Error!InstIndex {
        const index: u32 = try ip.instructions.addOne(alloc);
        return ip.allocInst(alloc, index, key);
    }

    fn allocInst(ip: *InternPool, alloc: Allocator, index: u32, key: Instruction) Allocator.Error!InstIndex {
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
        // debug("setInst: {}, index: {d}, size: {d}, key: {}", .{ opcode, index_int, key.size(), key });
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
                    .lt, .lte, .gt, .gte => |extra_data| {
                        ip.insertExtra(extra_index, extra_data);
                    },
                    .add, .subtract, .multiply, .divide, .remainder => |extra_data| {
                        ip.insertExtra(extra_index, extra_data);
                    },
                    .@"if", .if_not => |extra_data| {
                        ip.insertExtra(extra_index, extra_data);
                    },
                    .seek_gt, .seek_ge => |extra_data| {
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
                    .function => |extra_data| {
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
        // debug("getInst: {}, {d}", .{ item.opcode, item.data });
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
            .lt, .gt, .gte, .lte => {
                const extra_data = ip.extraData(Instruction.Lt, item.data);
                return switch (item.opcode) {
                    .lt => .{ .lt = extra_data },
                    .lte => .{ .lte = extra_data },
                    .gt => .{ .gt = extra_data },
                    .gte => .{ .gte = extra_data },
                    else => unreachable,
                };
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
            .function => {
                const extra_data = ip.extraData(Instruction.Function, item.data);
                return .{ .function = extra_data };
            },
            .@"if" => {
                const extra_data = ip.extraData(Instruction.If, item.data);
                return .{ .@"if" = extra_data };
            },
            .if_not => {
                const extra_data = ip.extraData(Instruction.If, item.data);
                return .{ .if_not = extra_data };
            },
            .seek_gt => {
                const extra_data = ip.extraData(Instruction.Seek, item.data);
                return .{ .seek_gt = extra_data };
            },
            .seek_ge => {
                const extra_data = ip.extraData(Instruction.Seek, item.data);
                return .{ .seek_ge = extra_data };
            },
            .add => {
                const extra_data = ip.extraData(Instruction.Operation, item.data);
                return .{ .add = extra_data };
            },
            .subtract => {
                const extra_data = ip.extraData(Instruction.Operation, item.data);
                return .{ .subtract = extra_data };
            },
            .multiply => {
                const extra_data = ip.extraData(Instruction.Operation, item.data);
                return .{ .multiply = extra_data };
            },
            .divide => {
                const extra_data = ip.extraData(Instruction.Operation, item.data);
                return .{ .divide = extra_data };
            },
            .remainder => {
                const extra_data = ip.extraData(Instruction.Operation, item.data);
                return .{ .remainder = extra_data };
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

        const Marked = enum(u32) {
            none = std.math.maxInt(u32),
            _,

            pub fn toInst(self: Marked) InstIndex {
                return @enumFromInt(@intFromEnum(self));
            }
        };
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
        function: Instruction.Function,
        @"if": Instruction.If,
        if_not: Instruction.If,
        gt: Instruction.Lt,
        gte: Instruction.Lt,
        lt: Instruction.Lt,
        lte: Instruction.Lt,
        add: Instruction.Operation,
        subtract: Instruction.Operation,
        multiply: Instruction.Operation,
        divide: Instruction.Operation,
        remainder: Instruction.Operation,
        seek_gt: Instruction.Seek,
        seek_ge: Instruction.Seek,
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
                .seek_gt => .seek_gt,
                .seek_ge => .seek_ge,
                .column => .column,
                .open_read => .open_read,
                .result_row => .result_row,
                .next => .next,
                .transaction => .transaction,
                .function => .function,
                .@"if" => .@"if",
                .if_not => .if_not,
                .gt => .gt,
                .gte => .gte,
                .lt => .lt,
                .lte => .lte,
                .add => .add,
                .subtract => .subtract,
                .multiply => .multiply,
                .divide => .divide,
                .remainder => .remainder,
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
                .seek_gt, .seek_ge => @sizeOf(Instruction.Seek),
                .function => @sizeOf(Instruction.Function),
                .if_not, .@"if" => @sizeOf(Instruction.If),
                .lt, .lte, .gt, .gte => @sizeOf(Instruction.Lt),
                .add, .subtract, .multiply, .divide, .remainder => @sizeOf(Instruction.Operation),
                .column => @sizeOf(Instruction.Column),
                .next => @sizeOf(Instruction.Next),
                .transaction => @sizeOf(Instruction.Transaction),
                .string => @sizeOf(Instruction.String),
                .integer => @sizeOf(Instruction.Integer),
            };
        }

        const Operation = struct {
            lhs_reg: Register.Index,
            rhs_reg: Register.Index,
            result_reg: Register.Index,
        };

        const Lt = struct {
            lhs_reg: Register.Index,
            rhs_reg: Register.Index,
            jump: InstIndex,
            // TODO: affinity/coersion, bit masking
        };

        const Equal = struct {
            lhs_reg: Register.Index,
            rhs_reg: Register.Index,
            jump: InstIndex,
        };

        // Additional arguments are stored in the next incremented register(s) from the first_argument_register.
        // TODO: Do we care if an argument is a constant for performance reasons?
        const Function = struct {
            index: BuiltInFunctionIndex,
            first_argument_register: Register.Index,
            result_register: Register.Index,
        };

        // If compare_reg is zero, the comparison is considered false. Otherwise, true. Jump address if evaluated true
        const If = struct {
            compare_reg: Register.Index,
            jump_address: InstIndex,
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

        const Seek = struct {
            table: Index, // TODO: this should be a cursor index, not a table
            seek_key: Register.Index,
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

    const Function = struct {
        index: BuiltInFunctionIndex,
        first_argument: Index.Optional, // Argument key

        const Repr = struct {
            index: u32,
            arg: u32,
        };
    };

    const Argument = struct {
        term: Term,
        next_argument: Index.Optional,

        const Repr = struct {
            arg: u32,
            term_0: u32,
            term_1: u32,
        };
    };

    const Term = union(enum) {
        expression: Index.Optional, // Expression
        // DEPRECATED: group currently serves no utility and is not used. Repurpose for lists?
        group: Index.Optional, // Expression
        column: Index.Optional, // Column
        func: Index.Optional, // Function
        string: NullTerminatedString,
        int: i64,
        float: f64,

        const Repr = enum(u8) {
            expression,
            group,
            column,
            func,
            string,
            int,
            float,
        };

        pub fn isEmpty(self: Term) bool {
            return switch (self) {
                .expression, .group => |expr| expr == .none,
                else => false,
            };
        }

        pub fn isConstant(self: Term) bool {
            return switch (self) {
                .string, .int, .float => true,
                else => false,
            };
        }

        pub fn is64(self: Term) bool {
            return switch (self) {
                .int => |val| val > std.math.maxInt(u32),
                .float => true,
                else => false,
            };
        }

        pub fn pack64(self: Term) PackedU64 {
            return switch (self) {
                .int => |val| PackedU64.init(val),
                .float => |val| PackedU64.init(val),
                .string => |val| .{ .a = @intFromEnum(val), .b = 0 },
                .expression, .group, .column, .func => |val| .{ .a = @intFromEnum(val), .b = 0 },
            };
        }

        pub fn pack32(self: Term) u32 {
            return switch (self) {
                .int => |val| @bitCast(@as(i32, @truncate(val))),
                .float => unreachable, // Can only use 64 bit to pack floats
                .string => |val| @intFromEnum(val),
                .expression, .group, .column, .func => |val| @intFromEnum(val),
            };
        }

        pub fn unpack64(repr: Repr, val: PackedU64) Term {
            return switch (repr) {
                .int => .{ .int = @bitCast(val.unwrap()) },
                .float => .{ .float = @bitCast(val.unwrap()) },
                .string => .{ .string = @enumFromInt(val.a) },
                .expression => .{ .expression = @enumFromInt(val.a) },
                .group => .{ .group = @enumFromInt(val.a) },
                .column => .{ .column = @enumFromInt(val.a) },
                .func => .{ .func = @enumFromInt(val.a) },
            };
        }

        pub fn unpack32(repr: Repr, val: u32) Term {
            return switch (repr) {
                .int => .{ .int = val },
                .float => unreachable,
                .string => .{ .string = @enumFromInt(val) },
                .expression => .{ .expression = @enumFromInt(val) },
                .group => .{ .group = @enumFromInt(val) },
                .column => .{ .column = @enumFromInt(val) },
                .func => .{ .func = @enumFromInt(val) },
            };
        }

        pub fn tag(self: Term) Repr {
            return switch (self) {
                .expression => .expression,
                .group => .group,
                .column => .column,
                .func => .func,
                .string => .string,
                .int => .int,
                .float => .float,
            };
        }
    };

    const ResultColumn = struct {
        val: union(enum) {
            wildcard: void,
            table_wildcard: NullTerminatedString, // TODO: change to table index
            expr_alias: struct { expr: Index.Optional, alias: NullTerminatedString },
        },
        next_col: Index.Optional,

        const Repr = struct {
            next: u32,
            expr: u32,
            str: u32,
        };
    };

    const Expression = struct {
        operator: Expression.Operator,
        lhs: Term,
        rhs: Term,

        const Operator = enum(u8) {
            @"or",
            @"and",
            not,
            like,
            unary,
            eq,
            ne,
            lt,
            lte,
            gt,
            gte,
            add,
            minus,
            multiply,
            divide,
            remainder,

            pub fn isAndOr(self: Operator) bool {
                return switch (self) {
                    .@"or", .@"and" => true,
                    else => false,
                };
            }

            pub fn isMath(self: Operator) bool {
                return switch (self) {
                    .add, .minus, .multiply, .divide, .remainder => true,
                    else => false,
                };
            }

            pub fn isComparison(self: Operator) bool {
                return switch (self) {
                    .eq, .ne, .lt, .lte, .gt, .gte => true,
                    else => false,
                };
            }
        };

        pub fn hasExpressionChild(self: *const Expression) bool {
            inline for (0..2) |i| {
                const term = if (i == 0) self.lhs else self.rhs;
                switch (term) {
                    .expression, .group => |val| return val != .none,
                    else => {},
                }
            }
            return false;
        }

        pub fn hasColumnChild(self: *const Expression) bool {
            inline for (0..2) |i| {
                const term = if (i == 0) self.lhs else self.rhs;
                switch (term) {
                    .column => |val| return val != .none,
                    else => {},
                }
            }
            return false;
        }

        const Repr = struct {
            tag: u32,
            lhs: u32,
            rhs: u32,
        };

        const ReprBig = struct {
            tag: u32,
            lhs_0: u32,
            lhs_1: u32,
            rhs_0: u32,
            rhs_1: u32,
        };
    };

    // TODO: Cursor should be like register, not in InternPool but in VM.
    const Cursor = struct {
        index: u32,
    };

    const Key = union(enum) {
        table: Table,
        column: Column,
        result_column: ResultColumn,
        expression: Expression,
        cursor: Cursor,
        function: Function,
        argument: Argument,
    };

    pub fn dump(ip: *InternPool, index: Index.Optional) void {
        if (!debug_mode) return;
        const buf: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(@constCast(&buf));
        _ = ip.bufWrite(@constCast(&fbs), index) catch null;
        const slice = fbs.getWritten();
        debug("AST: {s}", .{slice});
    }

    // Since this is only used for debugging, we permit the use of recursion to make the code more readable/easier to implement
    fn bufWrite(ip: *InternPool, buffer: *FixedBufferStream([]u8), index: Index.Optional) anyerror!void {
        if (index.unwrap() == null) {
            _ = try buffer.write("NULL");
            return;
        }
        const key: Key = ip.indexToKey(index.unwrap().?);
        switch (key) {
            .expression => |expression_data| {
                // TODO: make into enum
                var group = false;
                var unary = false;
                switch (expression_data.operator) {
                    .eq => _ = try buffer.write("(EQ "),
                    .ne => _ = try buffer.write("(NE "),
                    .not => _ = try buffer.write("(NOT "),
                    .like => _ = try buffer.write("(LIKE "),
                    .lt => _ = try buffer.write("(LT "),
                    .lte => _ = try buffer.write("(LTE "),
                    .gt => _ = try buffer.write("(GT "),
                    .gte => _ = try buffer.write("(GTE "),
                    .add => _ = try buffer.write("(+ "),
                    .minus => _ = try buffer.write("(- "),
                    .multiply => _ = try buffer.write("(* "),
                    .divide => _ = try buffer.write("(/ "),
                    .remainder => _ = try buffer.write("(% "),
                    .@"and" => _ = try buffer.write("(AND "),
                    .@"or" => _ = try buffer.write("(OR "),
                    .unary => {
                        unary = true;
                    },
                }
                for (0..2) |i| {
                    const term = if (i == 0) expression_data.lhs else expression_data.rhs;
                    switch (term) {
                        .column => |column| {
                            try fmt.format(buffer.writer().any(), "COL_{d}", .{@intFromEnum(column)});
                        },
                        .func => |builtin_func| {
                            try ip.bufWrite(buffer, builtin_func);
                        },
                        .expression, .group => |expression_idx| {
                            switch (term) {
                                .group => {
                                    _ = try buffer.write("(");
                                    group = true;
                                },
                                else => {},
                            }
                            try ip.bufWrite(buffer, expression_idx);
                            if (group) {
                                group = false;
                                _ = try buffer.write(")");
                            }
                        },
                        .int => |int_value| try fmt.format(buffer.writer().any(), "{d}", .{int_value}),
                        .float => |float_value| try fmt.format(buffer.writer().any(), "{e}", .{float_value}),
                        .string => |str_value| try fmt.format(buffer.writer().any(), "'{s}'", .{str_value.slice(ip)}),
                    }
                    if (i == 0) {
                        if (unary) {
                            unary = false;
                            break;
                        }
                        _ = try buffer.write(", ");
                    } else {
                        _ = try buffer.write(")");
                    }
                }
            },
            .function => |func_data| {
                switch (func_data.index) {
                    .like => _ = try buffer.write("LIKE("),
                }
                if (func_data.first_argument != .none) {
                    try ip.bufWrite(buffer, func_data.first_argument);
                }
                _ = try buffer.write(")");
            },
            .argument => |arg_data| {
                switch (arg_data.term) {
                    .int => |int_value| try fmt.format(buffer.writer().any(), "{d}", .{int_value}),
                    .float => |float_value| try fmt.format(buffer.writer().any(), "{e}", .{float_value}),
                    .string => |str_value| try fmt.format(buffer.writer().any(), "'{s}'", .{str_value.slice(ip)}),
                    .column => |col_value| try fmt.format(buffer.writer().any(), "COL_{d}", .{@intFromEnum(col_value)}),
                    .expression, .group => |expr_value| try ip.bufWrite(buffer, expr_value),
                    .func => unreachable, // TODO: nested functions
                }
                if (arg_data.next_argument != .none) {
                    _ = try buffer.write(", ");
                    try ip.bufWrite(buffer, arg_data.next_argument);
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

    // Replaces values at index to index + item field count. All fields in item must be size u32.
    fn insertExtra(ip: *InternPool, index: u32, item: anytype) void {
        // const fields = @typeInfo(@TypeOf(item)).@"struct".fields;
        const fields = @typeInfo(@TypeOf(item)).Struct.fields;
        inline for (fields, 0..) |field, i| {
            ip.extra.items[index + i] = switch (field.type) {
                Index, Index.Optional, Register.Index, InstIndex, BuiltInFunctionIndex, NullTerminatedString, String => @intFromEnum(@field(item, field.name)),
                u32 => @bitCast(@field(item, field.name)),
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
                BuiltInFunctionIndex,
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
        return switch (item.tag) {
            .expression => @sizeOf(Expression.Repr),
            .expression_big,
            => @sizeOf(Expression.ReprBig),
            .table => @sizeOf(Table.Repr),
            .column => @sizeOf(Column.Repr),
            .cursor => @sizeOf(Cursor),
        };
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
            .expression => {
                const expr = key.expression;
                const lhs_tag = expr.lhs.tag();
                const rhs_tag = expr.rhs.tag();
                const tag: PackedU32 = .{ .a = @intFromEnum(expr.operator), .b = @intFromEnum(lhs_tag), .c = @intFromEnum(rhs_tag), .d = 0 };
                if (expr.lhs.is64() or expr.rhs.is64()) {
                    const lhs = expr.lhs.pack64();
                    const rhs = expr.rhs.pack64();
                    if (item == null) {
                        item = .{ .tag = .expression_big, .data = extra_len };
                    }
                    _ = try ip.extraPlaceAt(alloc, item.?, Expression.ReprBig{
                        .tag = tag.unwrap(),
                        .lhs_0 = lhs.a,
                        .lhs_1 = lhs.b,
                        .rhs_0 = rhs.a,
                        .rhs_1 = rhs.b,
                    });
                    ip.itemPlaceAt(index, item.?);
                } else {
                    const lhs = expr.lhs.pack32();
                    const rhs = expr.rhs.pack32();
                    if (item == null) {
                        item = .{ .tag = .expression, .data = extra_len };
                    }
                    _ = try ip.extraPlaceAt(alloc, item.?, Expression.Repr{
                        .tag = tag.unwrap(),
                        .lhs = lhs,
                        .rhs = rhs,
                    });
                    ip.itemPlaceAt(index, item.?);
                }
            },
            .result_column => {
                const col = key.result_column;
                if (item == null) {
                    item = .{ .tag = .result_column, .data = extra_len };
                }
                switch (col.val) {
                    .wildcard => {
                        item = .{ .tag = .result_column_wildcard, .data = @intFromEnum(col.next_col) };
                    },
                    .table_wildcard => |val| {
                        _ = try ip.extraPlaceAt(alloc, item.?, ResultColumn.Repr{
                            .next = @intFromEnum(col.next_col),
                            .str = @intFromEnum(val),
                            .expr = @intFromEnum(Index.Optional.none),
                        });
                    },
                    .expr_alias => |val| {
                        _ = try ip.extraPlaceAt(alloc, item.?, ResultColumn.Repr{
                            .next = @intFromEnum(col.next_col),
                            .str = @intFromEnum(val.alias),
                            .expr = @intFromEnum(val.expr),
                        });
                    },
                }
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
            .function => {
                const func = key.function;
                if (item == null) {
                    item = .{ .tag = .function, .data = extra_len };
                }
                _ = try ip.extraPlaceAt(alloc, item.?, Function.Repr{
                    .index = func.index.unwrap(),
                    .arg = @intFromEnum(func.first_argument),
                });
                ip.itemPlaceAt(index, item.?);
            },
            .argument => {
                const arg = key.argument;
                const tag: Tag = switch (arg.term) {
                    .string => .argument_string,
                    .int => .argument_int,
                    .float => .argument_float,
                    .expression => .argument_expression,
                    .column => .argument_column,
                    .group => unreachable, // TODO: implement
                    .func => unreachable, // TODO: implement nested functions
                };
                if (item == null) {
                    item = .{ .tag = tag, .data = extra_len };
                }
                const term: PackedU64 = switch (arg.term) {
                    .string => |expr_string| .{ .a = @intFromEnum(expr_string), .b = 0 },
                    .int => |expr_int| PackedU64.init(expr_int),
                    .float => |expr_float| PackedU64.init(expr_float),
                    .expression => |expr_index| .{ .a = @intFromEnum(expr_index), .b = 0 },
                    .group => unreachable, // TODO: implement
                    .column => |col_index| .{ .a = @intFromEnum(col_index), .b = 0 },
                    .func => unreachable, // TODO: implement nested functions
                };
                _ = try ip.extraPlaceAt(alloc, item.?, Argument.Repr{
                    .term_0 = term.a,
                    .term_1 = term.b,
                    .arg = @intFromEnum(arg.next_argument),
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
            .expression => {
                const extra_data: Expression.Repr = ip.extraData(Expression.Repr, item.data);
                const tag: PackedU32 = @bitCast(extra_data.tag);
                return .{ .expression = .{
                    .operator = @enumFromInt(tag.a),
                    .lhs = Term.unpack32(@enumFromInt(tag.b), extra_data.lhs),
                    .rhs = Term.unpack32(@enumFromInt(tag.c), extra_data.rhs),
                } };
            },
            .expression_big => {
                const extra_data: Expression.ReprBig = ip.extraData(Expression.ReprBig, item.data);
                const tag: PackedU32 = @bitCast(extra_data.tag);
                const lhs_packed: PackedU64 = .{ .a = extra_data.lhs_0, .b = extra_data.lhs_1 };
                const rhs_packed: PackedU64 = .{ .a = extra_data.rhs_0, .b = extra_data.rhs_1 };
                return .{ .expression = .{
                    .operator = @enumFromInt(tag.a),
                    .lhs = Term.unpack64(@enumFromInt(tag.b), lhs_packed),
                    .rhs = Term.unpack64(@enumFromInt(tag.c), rhs_packed),
                } };
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
            .result_column => {
                const extra_data = ip.extraData(ResultColumn.Repr, item.data);
                const expr: Index.Optional = @enumFromInt(extra_data.expr);
                if (expr == .none) {
                    return .{ .result_column = .{
                        .next_col = @enumFromInt(extra_data.next),
                        .val = .{ .table_wildcard = @enumFromInt(extra_data.str) },
                    } };
                }
                return .{ .result_column = .{
                    .next_col = @enumFromInt(extra_data.next),
                    .val = .{
                        .expr_alias = .{
                            .expr = @enumFromInt(extra_data.expr),
                            .alias = @enumFromInt(extra_data.str),
                        },
                    },
                } };
            },
            .result_column_wildcard => {
                return .{ .result_column = .{ .next_col = @enumFromInt(item.data), .val = .wildcard } };
            },
            .table => {
                const extra_data = ip.extraData(Table.Repr, item.data);
                const result: Table = .{ .name = extra_data.name, .page = extra_data.page, .first_column = extra_data.first_column };
                return .{ .table = result };
            },
            .function => {
                const extra_data = ip.extraData(Function.Repr, item.data);
                const result: Function = .{
                    .index = @enumFromInt(extra_data.index),
                    .first_argument = @enumFromInt(extra_data.arg),
                };
                return .{ .function = result };
            },
            .argument_string, .argument_expression, .argument_float, .argument_int, .argument_column => {
                const extra_data = ip.extraData(Argument.Repr, item.data);
                const packed_term: PackedU64 = .{ .a = extra_data.term_0, .b = extra_data.term_1 };
                const term: Term = switch (item.tag) {
                    .argument_string => .{ .string = @enumFromInt(packed_term.a) },
                    .argument_int => .{ .int = @bitCast(packed_term) },
                    .argument_float => .{ .float = @bitCast(packed_term) },
                    .argument_column => .{ .column = @enumFromInt(packed_term.a) },
                    .argument_expression => .{ .expression = @enumFromInt(packed_term.a) },
                    else => unreachable, // Only handling argument tags
                };
                const result: Argument = .{
                    .term = term,
                    .next_argument = @enumFromInt(extra_data.arg),
                };
                return .{ .argument = result };
            },
            .cursor => {
                const result: Cursor = .{ .index = item.data };
                return .{ .cursor = result };
            },
            .root => unreachable, // Just the root
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

    pub fn cast(buf: []u8) *SQLiteDbHeader {
        return @alignCast(@ptrCast(buf[0..sqlite_header_size]));
    }

    pub fn getPageSize(self: *SQLiteDbHeader) u16 {
        return @byteSwap(self.page_size);
    }

    pub fn getUsableSize(self: *SQLiteDbHeader) u16 {
        const usable: u16 = self.getPageSize() - self.reserved_space;
        assert(usable >= 480); // Valid SQLite table has a minimum usable space of 480 bytes
        return usable;
    }

    pub fn getVersion(self: *SQLiteDbHeader) u32 {
        return @byteSwap(self.sqlite_version_number);
    }
};

const SQLitePage = struct {
    buffer: []u8,
    db_header: *SQLiteDbHeader,

    pub fn init(buf: []u8, db_header: *SQLiteDbHeader) SQLitePage {
        return .{
            .buffer = buf,
            .db_header = db_header,
        };
    }

    pub fn headerStart(self: SQLitePage) []u8 {
        if (self.db_header == SQLiteDbHeader.cast(self.buffer)) {
            return self.buffer[sqlite_header_size..];
        }
        return self.buffer;
    }

    pub fn header(self: SQLitePage) *SQLiteBtHeader {
        const header_start_buffer = self.headerStart();
        return SQLiteBtHeader.cast(header_start_buffer);
    }

    pub fn cell(self: SQLitePage, index: u32) SQLiteInteriorCell {
        const header_start_buffer = self.headerStart();
        const bt_header = SQLiteBtHeader.cast(header_start_buffer);
        assert(bt_header.getPageType() == .table_interior);

        const cell_adr = bt_header.getCellAddr(header_start_buffer, index);
        const cell_start = self.buffer[cell_adr..];

        return SQLiteInteriorCell.init(cell_start);
    }

    pub fn record(self: SQLitePage, index: u32) SQLiteRecord {
        const header_start_buffer = self.headerStart();
        const bt_header = SQLiteBtHeader.cast(header_start_buffer);
        assert(bt_header.getPageType() == .table_leaf);

        const cell_adr = bt_header.getCellAddr(header_start_buffer, index);
        const cell_start = self.buffer[cell_adr..];

        return SQLiteRecord.init(cell_start);
    }
};

const SQLitePageType = enum(u8) {
    table_leaf = 0x0d,
    table_interior = 0x05,
    index_leaf = 0x0a,
    index_interior = 0x02,
};

const sqlite_bt_header_size = 12;
const SQLiteBtHeader = extern struct {
    metadata: [8]u8,
    // Doesn't exist on leaf pages (0x0D and 0x0A page_type)
    right_child_page: u32,

    pub fn cast(buf: []u8) *SQLiteBtHeader {
        return @alignCast(@ptrCast(buf[0..sqlite_bt_header_size]));
    }

    pub fn getCellAddr(self: *const SQLiteBtHeader, buffer: []u8, index: u32) u16 {
        const bt_header_size = self.getHeaderSize();
        const start = bt_header_size + (index * 2);
        const cell_adr: u16 = @byteSwap(valFromSlice(u16, buffer[start .. start + 2]));
        return cell_adr;
    }

    pub fn getHeaderSize(self: *const SQLiteBtHeader) u8 {
        const page_type = self.getPageType();
        switch (page_type) {
            .table_leaf, .index_leaf => {
                return 8;
            },
            else => {
                return 12;
            },
        }
    }

    pub fn getPageType(self: *const SQLiteBtHeader) SQLitePageType {
        return @enumFromInt(self.metadata[0]);
    }

    pub fn getFirstFreeblock(self: *const SQLiteBtHeader) u16 {
        var block: u16 = 0;
        block = @as(u16, self.metadata[1]) << 8;
        block |= self.metadata[2];
        return block;
    }

    pub fn getCellCount(self: *const SQLiteBtHeader) u16 {
        var block: u16 = 0;
        block = @as(u16, self.metadata[3]) << 8;
        block |= self.metadata[4];
        return block;
    }

    pub fn getCellOffset(self: *const SQLiteBtHeader) u16 {
        var block: u16 = 0;
        block = @as(u16, self.metadata[5]) << 8;
        block |= self.metadata[6];
        return block;
    }

    pub fn getFragmentCount(self: *const SQLiteBtHeader) u8 {
        return self.metadata[7];
    }

    pub fn getRightChildPage(self: *const SQLiteBtHeader) u32 {
        assert(self.getPageType() != .table_leaf and self.getPageType() != .index_leaf);
        return @byteSwap(self.right_child_page);
    }
};

// Bit masks for getVarint
const bits_7: u8 = 0x7f;
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

// Enable debug printing to console by compiling with -Ddebug
const debug_mode: bool = config.is_debug;

fn debug(comptime format: []const u8, args: anytype) void {
    if (!debug_mode) return;
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
        result.* = (@as(u64, ptr[0] & bits_7) << 7) | ptr[1];
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
    std.debug.panic("uh oh I pwanic -><- uwu ", .{});
}

const TokenType = enum {
    number,
    plus,
    minus,
    asterisk,
    divide,
    percent,
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
    keyword_as,
    keyword_create,
    keyword_table,
    keyword_integer,
    keyword_in,
    keyword_primary,
    keyword_key,
    keyword_like,
    keyword_text,
    keyword_select,
    keyword_from,
    keyword_where,
    keyword_and,
    keyword_or,
    keyword_not,
    invalid,

    pub fn lexeme(token_type: TokenType) ?[]const u8 {
        return switch (token_type) {
            .asterisk => "*",
            .divide => "/",
            .plus => "+",
            .minus => "-",
            .comma => ",",
            .eq => "=",
            .lparen => "(",
            .ne => "!=",
            .lt => "<",
            .gt => ">",
            .lte => "<=",
            .gte => ">=",
            .rparen => ")",
            .semicolon => ";",
            .keyword_and => "AND",
            .keyword_as => "AS",
            .keyword_create => "CREATE",
            .keyword_from => "FROM",
            .keyword_in => "IN",
            .keyword_integer => "INTEGER",
            .keyword_key => "KEY",
            .keyword_like => "LIKE",
            .keyword_not => "NOT",
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
        .{ "as", TokenType.keyword_as },
        .{ "create", TokenType.keyword_create },
        .{ "from", TokenType.keyword_from },
        .{ "in", TokenType.keyword_in },
        .{ "integer", TokenType.keyword_integer },
        .{ "key", TokenType.keyword_key },
        .{ "like", TokenType.keyword_like },
        .{ "not", TokenType.keyword_not },
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
        gt,
        lt,
        eq,
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
            debug("{s}", .{word});
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
                    'a'...'z', 'A'...'Z', '_' => {
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
                    '\'' => {
                        state = .single_quote_word;
                    },
                    ';' => {
                        token.type = .semicolon;
                        self.index += 1;
                        break;
                    },
                    '=' => {
                        state = .eq;
                    },
                    '>' => {
                        state = .gt;
                    },
                    '<' => {
                        state = .lt;
                    },
                    '!' => {
                        state = .exclamation;
                    },
                    '*' => {
                        token.type = .asterisk;
                        self.index += 1;
                        break;
                    },
                    '+' => {
                        token.type = .plus;
                        self.index += 1;
                        break;
                    },
                    '-' => {
                        token.type = .minus;
                        self.index += 1;
                        break;
                    },
                    '/' => {
                        token.type = .divide;
                        self.index += 1;
                        break;
                    },
                    '%' => {
                        token.type = .percent;
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
                    'a'...'z', 'A'...'Z', '0'...'9', '_' => {},
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
                .gt => switch (c) {
                    '=' => {
                        token.type = TokenType.gte;
                        self.index += 1;
                        break;
                    },
                    else => {
                        token.type = TokenType.gt;
                        break;
                    },
                },
                .eq => switch (c) {
                    '=' => {
                        token.type = TokenType.eq;
                        self.index += 1;
                        break;
                    },
                    else => {
                        token.type = TokenType.eq;
                        break;
                    },
                },
                .lt => switch (c) {
                    '=' => {
                        token.type = TokenType.lte;
                        self.index += 1;
                        break;
                    },
                    '>' => {
                        token.type = TokenType.ne;
                        self.index += 1;
                        break;
                    },
                    else => {
                        token.type = TokenType.lt;
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
                        // TODO: probably want to support more characters
                        token.type = TokenType.invalid;
                    },
                },
                .single_quote_word => switch (c) {
                    'a'...'z', 'A'...'Z', '0'...'9', '_' => {},
                    '\'' => {
                        token.type = TokenType.single_quote_word;
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
    columns: InternPool.Index.Optional, // ResultColumns index
    table: InternPool.Index, // table index
    where: InternPool.Index.Optional, // Optional expression index
};

const SQLiteDbTable = struct {
    page: u32,
    sql: InternPool.NullTerminatedString,
};

const SQLiteInteriorCell = struct {
    page: u32, // Page the data is located
    int_key: u64, // cell offset on that page. Equal to row_id

    pub fn init(buffer: []u8) SQLiteInteriorCell {
        var int_key: u64 = 0;
        _ = getVarint(buffer[@sizeOf(u32)..].ptr, &int_key);
        return .{
            .page = @byteSwap(valFromSlice(u32, buffer)),
            .int_key = int_key,
        };
    }
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

    pub fn init(buffer: []u8) SQLiteRecord {
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
        return .{
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

    // TODO: rewrite. SQLiteColumn can overflow over multiple database pages
    // we need to handle that. Typically the record header is all stored in the payload of one cell, but the body can overflow to other pages
    pub fn next(self: *SQLiteRecord) ?SQLiteColumn {
        // Cursor can eq size and it still return a value if the value takes up 0 bytes (for e.g., 1, which is stored in the header)
        if (self.cursor > self.size) return null;
        if (self.header_cursor >= self.header_size) {
            self.header_cursor = 0;
        }
        var header_val: u64 = 0;
        self.header_cursor += getVarint(self.buffer.ptr + self.header_cursor, &header_val);

        const size: u32 = @truncate(SQLiteColumn.size(header_val));

        if (self.cursor + size > self.size) return null;

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
        // TODO: remove after finished debugging
        const size: u32 = @truncate(SQLiteColumn.size(header_val));
        const result = SQLiteColumn.from(
            header_val,
            self.buffer[self.cursor..],
        );
        debug("next() size: {d} col_type: {s}", .{ size, @tagName(result) });

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
                    // Compiler should be smart enough to optimize / 2
                    return (val - 12) / 2;
                }
                return (val - 13) / 2;
            },
        }
    }
};

pub const Error = error{ InvalidBinary, InvalidSyntax, OutOfMemory, NotImplemented };

const Db = struct {
    memory: DbMemory,
    page_size: u16,

    pub fn init(memory: DbMemory) Error!Db {
        if (memory.buffer.len < @sizeOf(SQLiteDbHeader)) {
            debug("buffer too small.", .{});
            return error.InvalidBinary;
        }
        const header = SQLiteDbHeader.cast(memory.buffer);
        const page_size = header.getPageSize();
        debug("page_size: {d}", .{page_size});
        return .{
            .memory = memory,
            .page_size = page_size,
        };
    }

    // TODO: support multi-layer interior pages (recursive)
    pub fn getRecord(self: *Db, table_root_page_index: u32, index: u32) ?SQLiteRecord {
        const root = self.readPage(table_root_page_index);
        const cell_count = root.header().getCellCount();

        debug("getRecord index: {d}", .{index});
        if (root.header().getPageType() == .table_interior) {
            const first_cell = root.cell(0);
            if (index < first_cell.int_key) {
                const page = self.readPage(first_cell.page - 1);
                return page.record(index);
            }
            // TODO: support 64 bit indices
            var base_int_key: u32 = @truncate(first_cell.int_key);
            var cell = root.cell(0);
            for (1..cell_count) |i| {
                cell = root.cell(i);
                if (index < cell.int_key) {
                    const page = self.readPage(cell.page - 1);
                    return page.record(index - base_int_key);
                }
                base_int_key = @truncate(cell.int_key);
            }
            const page = self.readPage(cell.page);
            if (index - base_int_key < page.header().getCellCount()) {
                return page.record(index - base_int_key);
            }
        } else if (root.header().getPageType() == .table_leaf) {
            if (index < root.header().getCellCount()) {
                return root.record(index);
            }
            return null;
        }
        return null;
    }

    pub fn readPage(self: *Db, index: u32) SQLitePage {
        debug("index: {d}, page_size: {d}", .{ index, self.page_size });
        const page_start: u32 = index * self.page_size;
        const page_end: u32 = page_start + self.page_size;
        debug("page start {x}", .{page_start});
        assert(page_end <= self.memory.max_allocated);
        // TODO: currently we are handling loading pages by loading up into the page address needed.
        // Instead, we could do a LRU cache of database pages (page index and location in memory)
        // TODO: we want to pre-load a lot of memory instead of loading with every page miss. So we have a warm cache.
        // this matters a lot for incremental select all statements
        if (self.memory.buffer.len < page_end) {
            debug("increasing buffer size", .{});
            // const length = page_start + self.page_size;
            const length_max = self.memory.max_allocated;
            readBuffer(self.memory.buffer.ptr, 0, length_max);
            const new_slice = self.memory.buffer.ptr[0..length_max]; // first page
            self.memory.buffer = new_slice;
            debug("allocated", .{});
        }
        debug("buffer len: {d}, page_start: {d}", .{ self.memory.buffer.len, page_start });
        const db_header = SQLiteDbHeader.cast(self.memory.buffer);
        return SQLitePage.init(self.memory.buffer[page_start..page_end], db_header);
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
        //
        // The first page contains the schemas of all tables in the database
        var page = self.readPage(0);

        var cell_index: u32 = 0;
        while (cell_index < page.header().getCellCount()) : (cell_index += 1) {
            var record = page.record(cell_index);
            debug("table record: {}", .{record});
            record.consume();
            record.consume();

            if (record.next()) |name_col| {
                if (name_col != SQLiteColumn.text) return Error.InvalidBinary;
                debug("record text: {s}", .{name_col.text});
                if (std.mem.eql(u8, table_name, name_col.text)) {
                    if (record.next()) |index_col| {
                        const index_int = index_col.getInt();
                        if (index_int == null) return Error.InvalidBinary;
                        assert(index_int.? >= 0);
                        const page_index: u32 = @intCast(index_int.?);
                        debug("found table '{s}' with page_index: {d}", .{ name_col.text, page_index });
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
        // TODO: probably do more then log that the table doesn't exist
        debug("Could not find table: {s}", .{table_name});
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
        expr_root,
        expr_andor,
        expr_operator,
        expr_lhs,
        expr_rhs,
        from,
        from_after,
        select_first,
        select_second,
        select_second_alias,
        select_column,
        start,
        table,
        table_col_name,
        table_col_primary,
        table_col_type,
        table_name,
        table_next,
        where,
    };

    pub fn init(
        gpa: Allocator,
        token_list: *TokenList,
        intern_pool: *InternPool,
        source: [:0]u8,
        db: Db,
    ) ASTGen {
        return .{
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
                    switch (token.tag) {
                        .keyword_integer => {
                            tag = .integer;
                            state = .table_next;
                        },
                        .keyword_text => {
                            tag = .text;
                            state = .table_next;
                        },
                        .keyword_primary => {
                            // If this is a primary key, we don't have to set the column type. It will act as autoincrement int.
                            tag = .null;
                            if (primary_key != PrimaryKeyState.unfilled) {
                                return Error.InvalidSyntax; // Primary key already filled
                            }
                            state = .table_col_primary;
                        },
                        else => {
                            // If the col type is invalid, sqlite defaults to a integer column type
                            tag = .integer;
                            state = .table_next;
                        },
                    }
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
                    debug("table_col_primary", .{});
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
        var table: ?InternPool.Index = null;
        const column_list_index: u32 = self.index;
        var processed_columns: bool = false;
        var where: InternPool.Index.Optional = .none;
        var result_columns: InternPool.Index.Optional = .none;
        var tail_column: InternPool.Index.Optional = .none;
        while (self.index < self.token_list.len) : (self.index += 1) {
            const token = self.token_list.get(self.index);
            switch (state) {
                .select_first => {
                    switch (token.tag) {
                        .keyword_from => {
                            state = .from;
                        },
                        else => {},
                    }
                },
                .select_second => {
                    debug("select_second, {}", .{token.tag});
                    switch (token.tag) {
                        .asterisk => {
                            const last_column_opt = tail_column;
                            tail_column = (try self.ip.put(self.gpa, .{
                                .result_column = .{
                                    .val = .wildcard,
                                    .next_col = .none,
                                },
                            })).toOptional();
                            if (last_column_opt.unwrap()) |last_column| {
                                var col = self.ip.indexToKey(last_column).result_column;
                                col.next_col = tail_column;
                                try self.ip.update(self.gpa, last_column, .{ .result_column = col });
                            } else {
                                result_columns = tail_column;
                            }
                        },
                        .comma => {},
                        .keyword_from => {
                            processed_columns = true;
                            debug("keyword_from -> from_after", .{});
                            state = .from_after;
                        },
                        .keyword_as => {
                            state = .select_second_alias;
                        },
                        else => {
                            const last_column_opt = tail_column;
                            debug("before buildExpression", .{});
                            const expr_idx = self.buildExpressionPrecedence(table.?, .none) catch return Error.InvalidSyntax;
                            tail_column = (try self.ip.put(self.gpa, .{
                                .result_column = .{
                                    .val = .{ .expr_alias = .{ .expr = expr_idx, .alias = .empty } },
                                    .next_col = .none,
                                },
                            })).toOptional();
                            debug("select second: {}", .{tail_column});
                            if (last_column_opt.unwrap()) |last_column| {
                                var col = self.ip.indexToKey(last_column).result_column;
                                col.next_col = tail_column;
                                try self.ip.update(self.gpa, last_column, .{ .result_column = col });
                            } else {
                                result_columns = tail_column;
                            }
                            // Expression reads up until comma or from, so we need to re-adjust the index
                            self.index -= 1;
                        },
                    }
                },
                .select_second_alias => {
                    switch (token.tag) {
                        .word, .single_quote_word, .double_quote_word => {
                            const update_col_idx = tail_column;
                            if (update_col_idx.unwrap()) |idx| {
                                var update_col = self.ip.indexToKey(idx).result_column;
                                switch (update_col.val) {
                                    .expr_alias => {
                                        const string_literal = ASTGen.getTokenSource(self.source, token);
                                        debug("alias literal: {s}", .{string_literal});
                                        const str = try InternPool.NullTerminatedString.initAddSentinel(
                                            self.gpa,
                                            if (token.tag == .word) string_literal else string_literal[1 .. string_literal.len - 1],
                                            self.ip,
                                        );
                                        update_col.val.expr_alias.alias = str;
                                        try self.ip.update(self.gpa, idx, .{ .result_column = update_col });
                                    },
                                    .wildcard, .table_wildcard => return Error.InvalidSyntax,
                                }
                                state = .select_second;
                            } else {
                                return Error.InvalidSyntax;
                            }
                        },
                        else => return Error.InvalidSyntax,
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
                    debug("from after: {}", .{token.tag});
                    switch (token.tag) {
                        .word => {}, // This is the table name. // TODO enforce table name before where clause or pop back to after table name after second_select
                        .keyword_where => {
                            state = .where;
                        },
                        else => break,
                    }
                },
                .where => {
                    where = try self.buildExpressionPrecedence(table.?, result_columns);
                    self.ip.dump(where);
                    // TODO: support other keywords after where and check for semicolon
                    state = .end;
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
            .columns = result_columns,
            .table = table.?,
            .where = where,
        };
    }

    const OperInfo = struct {
        prec: i8,
        op: InternPool.Expression.Operator,
        assoc_left: bool = false,
    };

    // https://www.sqlite.org/lang_expr.html#operators_and_parse_affecting_attributes
    const operTable = std.enums.directEnumArrayDefault(TokenType, OperInfo, .{ .prec = -1, .op = InternPool.Expression.Operator.@"or" }, 0, .{
        .keyword_or = .{ .prec = 0, .op = .@"or" },
        .keyword_and = .{ .prec = 1, .op = .@"and" },
        .keyword_not = .{ .prec = 2, .op = .not },
        .eq = .{ .prec = 3, .op = .eq },
        .ne = .{ .prec = 3, .op = .ne },
        .keyword_like = .{ .prec = 3, .op = .like },
        .gt = .{ .prec = 4, .op = .gt },
        .gte = .{ .prec = 4, .op = .gte },
        .lt = .{ .prec = 4, .op = .lt },
        .lte = .{ .prec = 4, .op = .lte },
        .plus = .{ .prec = 7, .op = .add },
        .minus = .{ .prec = 7, .op = .minus },
        .asterisk = .{ .prec = 8, .op = .multiply },
        .divide = .{ .prec = 8, .op = .divide },
        .percent = .{ .prec = 8, .op = .remainder },
    });

    fn buildExpressionNode(self: *ASTGen, or_list: *std.ArrayListUnmanaged(TokenType), and_list: *std.ArrayListUnmanaged(InternPool.Term), is_group: bool) Error!void {
        if (or_list.items.len == 0) return Error.InvalidSyntax;
        if (and_list.items.len < 2) return Error.InvalidSyntax;
        const token: TokenType = or_list.pop();
        const right: InternPool.Term = and_list.pop();
        const left: InternPool.Term = and_list.pop();
        const op_info = operTable[@as(usize, @intCast(@intFromEnum(token)))];
        const index = try self.ip.put(self.gpa, .{
            .expression = .{ .operator = op_info.op, .lhs = left, .rhs = right },
        });
        const term: InternPool.Term = if (is_group) .{ .group = index.toOptional() } else .{ .expression = index.toOptional() };
        try and_list.append(self.gpa, term);
    }

    pub fn buildExpressionPrecedence(self: *ASTGen, table: InternPool.Index, aliases: InternPool.Index.Optional) Error!InternPool.Index.Optional {
        var operator_list: std.ArrayListUnmanaged(TokenType) = .{};
        defer operator_list.deinit(self.gpa);
        var operand_list: std.ArrayListUnmanaged(InternPool.Term) = .{};
        defer operand_list.deinit(self.gpa);

        while (self.index < self.token_list.len) : (self.index += 1) {
            const token = self.token_list.get(self.index);
            debug("[expr] token: {}", .{token});

            switch (token.tag) {
                .word, .double_quote_word => {
                    // TODO: support function syntax. For e.g. like('%a', col)
                    var col_index: InternPool.Index.Optional = .none;
                    const column_token_slice = ASTGen.getTokenSource(self.source, token);
                    const column_name = if (token.tag == .double_quote_word) column_token_slice[1 .. column_token_slice.len - 1] else column_token_slice;
                    const col_optional = self.ip.columnFromName(table, column_name);
                    if (col_optional) |col| {
                        col_index = col.index.toOptional();
                    } else if (aliases.unwrap()) |alias_idx| {
                        const col_opt = self.findAliasColumn(alias_idx, column_name);
                        if (col_opt) |col| {
                            col_index = col.toOptional();
                        }
                    } else {
                        return Error.InvalidSyntax; // Column doesn't exist
                    }
                    try operand_list.append(self.gpa, .{ .column = col_index });
                },
                .single_quote_word => {
                    const string_literal = ASTGen.getTokenSource(self.source, token);
                    debug("build_expr literal: {s}", .{string_literal});
                    const value = try InternPool.NullTerminatedString.initAddSentinel(self.gpa, string_literal[1 .. string_literal.len - 1], self.ip);
                    var term: InternPool.Term = .{ .expression = .none };
                    if (false) {} else if (aliases.unwrap()) |alias_idx| {
                        const col_opt = self.findAliasColumn(alias_idx, string_literal[1 .. string_literal.len - 1]);
                        if (col_opt) |col| {
                            term = .{ .column = col.toOptional() };
                        } else {
                            term = .{ .string = value };
                        }
                    } else {
                        term = .{ .string = value };
                    }
                    try operand_list.append(self.gpa, term);
                },
                .integer => {
                    const slice = ASTGen.getTokenSource(self.source, token);
                    const value: i64 = fmt.parseInt(i64, slice, 10) catch return Error.InvalidSyntax;
                    try operand_list.append(self.gpa, .{ .int = value });
                },
                .eq, .ne, .lt, .lte, .gt, .gte, .plus, .minus, .asterisk, .divide, .percent, .keyword_and, .keyword_or, .keyword_like => {
                    const cur_op = operTable[@as(usize, @intCast(@intFromEnum(token.tag)))];
                    while (operator_list.items.len > 0) {
                        const top_token: TokenType = operator_list.items[operator_list.items.len - 1];
                        if (top_token == .lparen) break;
                        const top_op = operTable[@as(usize, @intCast(@intFromEnum(top_token)))];
                        if (top_op.prec > cur_op.prec) {
                            try self.buildExpressionNode(&operator_list, &operand_list, false);
                        } else {
                            break;
                        }
                    }
                    try operator_list.append(self.gpa, token.tag);
                },
                .lparen => {
                    try operator_list.append(self.gpa, token.tag);
                },
                .rparen => {
                    while (operator_list.items.len > 0 and operator_list.items[operator_list.items.len - 1] != .lparen) {
                        // const is_next_lparen = operator_list.items.len > 1 and operator_list.items[operator_list.items.len - 2] == .lparen;
                        try self.buildExpressionNode(&operator_list, &operand_list, false);
                    }
                    if (operator_list.items.len == 0) return Error.InvalidSyntax; // Parameter mismatch
                    _ = operator_list.pop(); // Remove the lparen
                },
                .comma => break, // TODO: add logic to support lists, functions
                else => {
                    debug("expr unexpected token '{}', terminating expr.", .{token});
                    break;
                },
            }
        }

        while (operator_list.items.len > 0) {
            const top_token: TokenType = operator_list.items[operator_list.items.len - 1];
            if (top_token == .lparen or top_token == .rparen) {
                debug("mismatched brackets: {}", .{top_token});
                return Error.InvalidSyntax;
            } // Mismatched brackets
            try self.buildExpressionNode(&operator_list, &operand_list, false);
        }

        if (operand_list.items.len != 1) return Error.InvalidSyntax; // Final term
        const final: InternPool.Term = operand_list.pop();
        switch (final) {
            .expression => |expr| return expr,
            else => {
                return (try self.ip.put(self.gpa, .{
                    .expression = .{ .operator = .unary, .lhs = final, .rhs = .{ .expression = .none } },
                })).toOptional();
            },
        }
    }

    fn findAliasColumn(self: *ASTGen, aliases: InternPool.Index, slice: []const u8) ?InternPool.Index {
        var idx_opt = aliases.toOptional();
        while (idx_opt.unwrap()) |idx| {
            const result_col = self.ip.indexToKey(idx).result_column;
            switch (result_col.val) {
                .expr_alias => |val| {
                    if (std.mem.eql(u8, val.alias.slice(self.ip), slice)) {
                        // TODO: the expr should be returned and processed in replacement of the column.
                        // This fn should also be renamed findAliasExpr
                        if (val.expr == .none) return null;
                        const expr = self.ip.indexToKey(val.expr.unwrap().?).expression;
                        if (expr.operator != .unary) return null;
                        switch (expr.lhs) {
                            .column => |col_idx_opt| {
                                return col_idx_opt.unwrap();
                            },
                            else => return null,
                        }
                    }
                },
                else => {},
            }
            idx_opt = result_col.next_col;
        }
        return null;
    }

    pub fn buildExpression(self: *ASTGen, table: InternPool.Index, aliases: InternPool.Index.Optional) Error!InternPool.Index.Optional {
        var state: State = .expr_lhs;
        var operator: ?TokenType = null;
        var last_element_andor = false;
        var is_like = false;
        var last_generated_expr_index: InternPool.Index.Optional = .none;
        var lhs_term: ?InternPool.Term = null;
        var grouping = false;

        var open_roots: ArrayListUnmanaged(InternPool.Index.Optional) = .{};
        defer open_roots.deinit(self.gpa);
        try open_roots.append(self.gpa, .none);

        debug("buildExpression", .{});
        while (self.index < self.token_list.len) : (self.index += 1) {
            const token = self.token_list.get(self.index);
            debug("[expr] token: {}, state: {}", .{ token, state });
            switch (state) {
                .expr_lhs, .expr_rhs => {
                    if (state == .expr_rhs) {
                        debug("expr_rhs eq: {?}, lhs_term: {?}", .{ operator, lhs_term });
                        if (operator == null or lhs_term == null) {
                            debug("expr missing", .{});
                            return Error.InvalidSyntax;
                        }
                    }
                    var term: ?InternPool.Term = null;
                    switch (token.tag) {
                        .word, .double_quote_word => {
                            // TODO: support function syntax. For e.g. like('%a', col)
                            const column_token_slice = ASTGen.getTokenSource(self.source, token);
                            const column_name = if (token.tag == .double_quote_word) column_token_slice[1 .. column_token_slice.len - 1] else column_token_slice;
                            const col_optional = self.ip.columnFromName(table, column_name);
                            if (col_optional) |col| {
                                term = .{ .column = col.index.toOptional() };
                            } else if (aliases.unwrap()) |alias_idx| {
                                const col_opt = self.findAliasColumn(alias_idx, column_name);
                                if (col_opt) |col| {
                                    term = .{ .column = col.toOptional() };
                                }
                            } else {
                                return Error.InvalidSyntax; // Column doesn't exist
                            }
                        },
                        .rparen => {
                            if (open_roots.items.len == 1) break; // Too many closing brackets. Invalid
                            const last = open_roots.pop();
                            if (last.unwrap()) |last_idx| {
                                const last_expr = self.ip.indexToKey(last_idx).expression;
                                const ignore_group = switch (last_expr.operator) {
                                    .@"and", .@"or" => false,
                                    else => true,
                                };
                                const new_root_index_opt = open_roots.items[open_roots.items.len - 1];
                                if (new_root_index_opt.unwrap()) |new_root_index| {
                                    var cur = self.ip.indexToKey(new_root_index).expression;
                                    switch (cur.operator) {
                                        .@"and", .@"or" => {},
                                        else => return Error.InvalidSyntax,
                                    }
                                    if (cur.lhs.isEmpty()) {
                                        cur = .{
                                            .lhs = if (ignore_group) .{ .expression = last } else .{ .group = last },
                                            .rhs = cur.rhs,
                                            .operator = cur.operator,
                                        };
                                    } else {
                                        cur = .{
                                            .lhs = cur.lhs,
                                            .rhs = if (ignore_group) .{ .expression = last } else .{ .group = last },
                                            .operator = cur.operator,
                                        };
                                    }
                                    debug("rparen update index: {}", .{cur});
                                    try self.ip.update(self.gpa, new_root_index, .{ .expression = cur });
                                } else {
                                    if (!ignore_group) {
                                        grouping = true;
                                    }
                                    open_roots.items[open_roots.items.len - 1] = last;
                                }
                            }
                        },
                        .lparen => {
                            // if (!last_element_andor and last_generated_expr_index != .none) break; // open bracket only after and/or. TODO: other ignorable brackets such as (col_name)
                            try open_roots.append(self.gpa, .none);
                            debug("expr open", .{});
                        },
                        // TODO: add eq, ne as well
                        .keyword_and, .keyword_or, .plus, .minus, .asterisk, .divide, .percent, .gt, .gte, .lt, .lte => {
                            if (last_element_andor) {
                                // TODO: cannot do and or if last token is operator too
                                debug("not valid place for and/or", .{});
                                break;
                            }
                            const last_root = open_roots.items[open_roots.items.len - 1];
                            const andor_lhs: InternPool.Term = switch (last_root) {
                                .none => if (lhs_term) |val| val else .{ .expression = last_generated_expr_index },
                                else => if (grouping) .{ .group = last_root } else .{ .expression = last_root },
                            };
                            grouping = false;
                            const andor_rhs: InternPool.Term = switch (last_root) {
                                .none => .{ .expression = .none },
                                else => if (lhs_term) |val| val else .{ .expression = last_generated_expr_index },
                            };
                            const new_index = try self.ip.put(self.gpa, .{
                                .expression = .{
                                    .rhs = andor_rhs,
                                    .operator = switch (token.tag) {
                                        .keyword_and => .@"and",
                                        .keyword_or => .@"or",
                                        .plus => .add,
                                        .minus => .minus,
                                        .asterisk => .multiply,
                                        .divide => .divide,
                                        .percent => .remainder,
                                        .gte => .gte,
                                        .gt => .gt,
                                        .lt => .lt,
                                        .lte => .lte,
                                        else => unreachable,
                                    },
                                    .lhs = andor_lhs,
                                },
                            });

                            lhs_term = null;
                            last_generated_expr_index = new_index.toOptional();
                            last_element_andor = true;
                            open_roots.items[open_roots.items.len - 1] = last_generated_expr_index;
                        },
                        .single_quote_word => {
                            const string_literal = ASTGen.getTokenSource(self.source, token);
                            debug("build_expr literal: {s}", .{string_literal});
                            const value = try InternPool.NullTerminatedString.initAddSentinel(self.gpa, string_literal[1 .. string_literal.len - 1], self.ip);
                            if (is_like) {
                                if (lhs_term == null) return Error.InvalidSyntax;
                                debug("build_expr like eq: {}", .{operator.?});
                                const match_arg = try self.ip.put(self.gpa, .{ .argument = .{
                                    .term = lhs_term.?,
                                    .next_argument = .none,
                                } });
                                const pattern_arg = try self.ip.put(self.gpa, .{ .argument = .{
                                    .term = .{
                                        .string = value,
                                    },
                                    .next_argument = match_arg.toOptional(),
                                } });
                                const func_lhs = try self.ip.put(self.gpa, .{ .function = .{
                                    .index = .like,
                                    .first_argument = pattern_arg.toOptional(),
                                } });
                                const new_index = try self.ip.put(self.gpa, .{
                                    .expression = .{
                                        .lhs = .{ .func = func_lhs.toOptional() },
                                        .operator = .unary,
                                        .rhs = .{ .expression = .none },
                                    },
                                });
                                last_generated_expr_index = new_index.toOptional();
                                debug("build_expr like complete", .{});
                                lhs_term = null;
                            } else if (aliases.unwrap()) |alias_idx| {
                                const col_opt = self.findAliasColumn(alias_idx, string_literal[1 .. string_literal.len - 1]);
                                if (col_opt) |col| {
                                    term = .{ .column = col.toOptional() };
                                } else {
                                    term = .{ .string = value };
                                }
                            } else {
                                term = .{ .string = value };
                            }
                        },
                        .integer => {
                            const slice = ASTGen.getTokenSource(self.source, token);
                            const value = fmt.parseInt(i64, slice, 10) catch break;
                            term = .{ .int = value };
                        },
                        .float => {
                            const slice = ASTGen.getTokenSource(self.source, token);
                            const value = fmt.parseFloat(f64, slice) catch break;
                            term = .{ .float = value };
                        },
                        else => {
                            if (last_element_andor) {
                                debug("Not a valid expression", .{});
                                break;
                            }
                            // Return the complete expression
                            if (open_roots.items[0].unwrap()) |index| {
                                return index.toOptional();
                            }
                            debug("No open_roots", .{});
                            break;
                        },
                    }
                    if (state == .expr_rhs and (term != null or is_like)) {
                        if (is_like) {
                            is_like = false;
                        } else {
                            const new_index = try self.ip.put(self.gpa, .{
                                .expression = .{
                                    .lhs = lhs_term.?,
                                    .operator = switch (operator.?) {
                                        .eq => .eq,
                                        .ne => .ne,
                                        .lt => .lt,
                                        .gt => .gt,
                                        .lte => .lte,
                                        .gte => .gte,
                                        .plus => .add,
                                        else => return Error.InvalidSyntax,
                                    },
                                    .rhs = term.?,
                                },
                            });
                            debug("expr rhs index: {}", .{new_index});
                            last_generated_expr_index = new_index.toOptional();
                        }
                        last_element_andor = false;
                        if (open_roots.items[open_roots.items.len - 1].unwrap()) |root| {
                            var key = self.ip.indexToKey(root);
                            debug("expr rhs: {}", .{key});
                            key.expression.rhs = .{ .expression = last_generated_expr_index.unwrap().?.toOptional() };
                            debug("expr rhs update: {}", .{key});
                            try self.ip.update(self.gpa, root, key);
                        } else {
                            open_roots.items[open_roots.items.len - 1] = last_generated_expr_index;
                        }
                        operator = null;
                        lhs_term = null;
                        state = .expr_lhs;
                    } else if (state == .expr_lhs and term != null) {
                        lhs_term = term;
                        state = .expr_operator;
                    }
                },
                .expr_operator => switch (token.tag) {
                    .eq, .ne, .lt, .lte, .gt, .gte, .plus => {
                        operator = token.tag;
                        debug("expr_operator: {}", .{operator.?});
                        state = .expr_rhs;
                    },
                    .keyword_like => {
                        operator = .eq;
                        is_like = true;
                        state = .expr_rhs;
                    },
                    .keyword_and, .keyword_or => {
                        // better at least have a LHS
                        if (lhs_term == null) return Error.InvalidSyntax;
                        // re-process as lhs
                        state = .expr_lhs;
                        self.index -= 1;
                    },
                    else => {
                        debug("Expression else: {?}, token: {}", .{ lhs_term, token });
                        if (lhs_term == null) return Error.InvalidSyntax;
                        if (open_roots.items[open_roots.items.len - 1].unwrap()) |root| {
                            var key = self.ip.indexToKey(root);
                            key.expression.rhs = lhs_term.?;
                            try self.ip.update(self.gpa, root, key);
                            last_element_andor = false;
                        } else {
                            const new_index = try self.ip.put(self.gpa, .{
                                .expression = .{
                                    .lhs = lhs_term.?,
                                    .operator = .unary,
                                    .rhs = .{ .expression = .none },
                                },
                            });
                            debug("expr unary index: {}", .{new_index});
                            last_generated_expr_index = new_index.toOptional();
                            open_roots.items[open_roots.items.len - 1] = last_generated_expr_index;
                        }
                        lhs_term = null;
                        // re-process token with expr_lhs state
                        state = .expr_lhs;
                        self.index -= 1;
                    },
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
    index: InternPool.Index.Optional,

    pub fn from(intern_pool: *InternPool, table_index: InternPool.Index) TableMetadataReader {
        const table = intern_pool.indexToKey(table_index).table;
        return .{
            .ip = intern_pool,
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

// This works by traversing the current node on the LHS and adding the nodes to the stack.
// fn next always assumes that its LHS has been fully traversed, and therefore looks at the RHS.
// Therefore, for init, we need to first traverse the LHS and provide the "leaf" for the first next call
const ExpressionTraversal = struct {
    ip: *InternPool,
    stack: Stack,
    first: InternPool.Index.Optional,

    // State is for the special case where there are expression on both sides
    // If state is none, it is a leaf node. Otherwise state is a dual expression node.
    const StackState = enum { in_order, middle, post_order, none };
    const StackItem = struct { op: InternPool.Expression.Operator, index: InternPool.Index, state: StackState };
    const ResultItem = struct { op: ?InternPool.Expression.Operator, index: InternPool.Index.Optional, pop: InternPool.Index.Optional, state: StackState };
    const Stack = ArrayListUnmanaged(StackItem);

    pub fn init(intern_pool: *InternPool, root: InternPool.Index.Optional) Allocator.Error!ExpressionTraversal {
        return .{
            .ip = intern_pool,
            .stack = .{},
            .first = root,
        };
    }

    pub fn parent(self: *ExpressionTraversal) ?StackItem {
        if (self.stack.items.len > 0) {
            return self.stack.items[self.stack.items.len - 1];
        }
        return null;
    }

    pub fn isValidSeekOptimization(self: *ExpressionTraversal) bool {
        if (self.stack.items.len == 0) return true;

        for (self.stack.items) |item| {
            if (item.op != .@"and") return false;
        }

        return true;
    }

    // Traverse the Expression tree in an interative, in-order DFS matter. ResultItem is:
    // Leaf - A comparison between two data types.
    // AndOr - and/or expression that connects between two leaf nodes (or other and/or expression). Outputted after the left side and before the right side
    pub fn next(self: *ExpressionTraversal, alloc: Allocator) Allocator.Error!?ResultItem {
        debug("next stack: {}", .{self.stack});
        if (self.first != .none) {
            var cur = self.first;
            self.first = .none;
            while (cur.unwrap()) |idx| {
                const expr = self.ip.indexToKey(idx).expression;
                if (expr.operator != .unary and expr.hasExpressionChild()) {
                    const state: StackState = if (expr.lhs.tag() == .expression or expr.lhs.tag() == .group) .in_order else .middle;
                    try self.stack.append(alloc, .{ .op = expr.operator, .index = idx, .state = state });
                }
                switch (expr.lhs) {
                    .expression, .group => |next_expr| {
                        cur = next_expr;
                    },
                    else => {
                        if (self.stack.items.len == 0) return .{
                            .op = null,
                            .index = cur,
                            .pop = .none,
                            .state = .none,
                        };
                        const parent_item = self.parent().?;
                        return .{ .op = parent_item.op, .index = cur, .pop = .none, .state = .none };
                    },
                }
            }
        }
        if (self.stack.popOrNull()) |pop| {
            const key = self.ip.indexToKey(pop.index).expression;
            var cur: InternPool.Index.Optional = .none;
            const rhs_expr: InternPool.Index.Optional = switch (key.rhs) {
                .expression, .group => |expr| expr,
                else => .none,
            };
            if (rhs_expr != .none and pop.state == .middle) {
                self.stack.appendAssumeCapacity(.{ .op = pop.op, .index = pop.index, .state = .post_order });
                cur = rhs_expr;
            } else {
                if (rhs_expr != .none and pop.state == .in_order) {
                    self.stack.appendAssumeCapacity(.{ .op = pop.op, .index = pop.index, .state = .middle });
                }
                const parent_item: ?StackItem = self.parent();
                const op: ?InternPool.Expression.Operator = if (parent_item) |item| item.op else null;
                return .{
                    .op = op,
                    .index = pop.index.toOptional(),
                    .pop = pop.index.toOptional(),
                    .state = pop.state,
                };
            }
            var prev: ?InternPool.Expression.Operator = null;
            while (cur.unwrap()) |idx| {
                const expr = self.ip.indexToKey(idx).expression;
                if (expr.operator != .unary and expr.hasExpressionChild()) {
                    const state: StackState = if (expr.lhs.tag() == .expression or expr.lhs.tag() == .group) .in_order else .middle;
                    try self.stack.append(alloc, .{ .op = expr.operator, .index = idx, .state = state });
                }
                switch (expr.lhs) {
                    .expression, .group => |next_expr| {
                        prev = expr.operator;
                        cur = next_expr;
                    },
                    else => {
                        return .{
                            .op = pop.op,
                            .index = cur,
                            .pop = pop.index.toOptional(),
                            .state = .none,
                        };
                    },
                }
            } else {
                return .{
                    .op = pop.op,
                    .index = .none,
                    .pop = pop.index.toOptional(),
                    .state = .none,
                };
            }
        }
        return null;
    }

    pub fn deinit(self: *ExpressionTraversal, alloc: Allocator) void {
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
    ) InstGen {
        return .{
            .gpa = gpa,
            .ip = intern_pool,
            .statement = statement,
            .db = db,
        };
    }

    fn replaceJump(self: *InstGen, index: InternPool.InstIndex, jump_address: InternPool.InstIndex) void {
        var inst = self.ip.getInst(index).?;
        switch (inst) {
            .eq => {
                inst.eq.jump = jump_address;
            },
            .neq => {
                inst.neq.jump = jump_address;
            },
            .rewind => {
                inst.rewind.end_inst = jump_address;
            },
            .next => {
                inst.next.success_jump = jump_address;
            },
            .@"if" => {
                inst.@"if".jump_address = jump_address;
            },
            .if_not => {
                inst.if_not.jump_address = jump_address;
            },
            .gt => {
                inst.gt.jump = jump_address;
            },
            .gte => {
                inst.gte.jump = jump_address;
            },
            .lt => {
                inst.lt.jump = jump_address;
            },
            .lte => {
                inst.lte.jump = jump_address;
            },
            else => unreachable, // Replace jump only on instructions with jump_address
        }
        self.ip.setInst(index, inst);
    }

    fn negate(self: *InstGen, index: InternPool.InstIndex) void {
        const old_inst = self.ip.getInst(index).?;
        debug("negate: {}", .{old_inst});
        const new_inst: InternPool.Instruction = switch (old_inst) {
            .eq => |data| .{ .neq = data },
            .neq => |data| .{ .eq = data },
            .@"if" => |data| .{ .if_not = data },
            .if_not => |data| .{ .@"if" = data },
            .lte => |data| .{ .gt = data },
            .lt => |data| .{ .gte = data },
            .gte => |data| .{ .lt = data },
            .gt => |data| .{ .lte = data },
            else => unreachable, // Can only negate eq/ne opcodes
        };
        self.ip.setInst(index, new_inst);
    }

    fn addInst(self: *InstGen, key: InternPool.Instruction) Allocator.Error!InternPool.InstIndex {
        return try self.ip.addInst(self.gpa, key);
    }

    const SeekOptimization = union(enum) {
        none,
        used,
        lt,
        le,
        gt,
        ge,
    };

    pub fn dump(self: *InstGen) void {
        if (!debug_mode) return;
        var i: u32 = 0;
        debug("--- Instructions ---", .{});
        while (i < self.ip.instructions.len) : (i += 1) {
            debug("[{d}] {}", .{ i, self.ip.getInst(@enumFromInt(i)).? });
        }
        debug("------", .{});
    }

    const Label = struct {
        inst: InternPool.InstIndex, // Instruction to modify
        jump: InternPool.InstIndex, // Instruction to jump to
        expr_index: InternPool.Index.Optional, // AST node instruction generated from
    };

    const LabelList = MultiArrayList(Label);

    fn addColumnInst(self: *InstGen, index: InternPool.Index, col: InternPool.Column, cursor: InternPool.Index, reg: Register.Index) Error!void {
        if (col.is_primary_key and col.tag == .integer) {
            _ = try self.addInst(.{ .row_id = .{
                .read_cursor = cursor,
                .store_reg = reg,
            } });
        } else {
            _ = try self.addInst(.{ .column = .{
                .cursor = cursor,
                .store_reg = reg,
                .col = index,
            } });
        }
    }

    // Label list pass. Now that we have the location of the output columns and all label comparison instructions,
    // we can fill in the jump locations
    fn fillLabels(
        self: *InstGen,
        labels: LabelList,
        where_clause: InternPool.Index.Optional,
        next_index: InternPool.InstIndex,
        columns_start: InternPool.InstIndex,
    ) Error!void {
        var li: usize = 0;
        const slice = labels.slice();
        var traverse = try ExpressionTraversal.init(self.ip, where_clause);
        defer traverse.deinit(self.gpa);
        var unresolved: ArrayListUnmanaged(struct { li: u32, idx: InternPool.Index }) = .{};
        defer unresolved.deinit(self.gpa);

        for (0..slice.len) |i| {
            debug("[label {d}] idx: {}, jmp: {}, inst: {}", .{ i, slice.items(.expr_index)[i], slice.items(.jump)[i], slice.items(.inst)[i] });
        }

        var traverse_next = try traverse.next(self.gpa);
        while (li < slice.len) : (li += 1) {
            const expr_idx = slice.items(.expr_index)[li];
            debug("slice expr_idx: {}", .{expr_idx});
            while (traverse_next != null and (traverse_next.?.index != expr_idx or traverse_next.?.state == .post_order)) : (traverse_next = try traverse.next(self.gpa)) {}
            if (traverse_next) |leaf| {
                debug("leaf: {}, expr_index: {}", .{ leaf, expr_idx });
                if (expr_idx != leaf.index) continue;
                const inst = slice.items(.inst)[li];
                debug("leaf inst: {}", .{inst});

                // check unresolved
                var ui: usize = 0;
                while (ui < unresolved.items.len) {
                    const item = unresolved.items[ui];
                    if (leaf.pop == item.idx.toOptional()) {
                        const item_inst = slice.items(.inst)[item.li];
                        const jump = slice.items(.jump)[li];
                        self.replaceJump(item_inst, jump);
                        _ = unresolved.swapRemove(ui);
                    } else {
                        ui += 1;
                    }
                }

                // add to unresolved
                if (li == slice.len - 1) {
                    self.negate(inst);
                    self.replaceJump(inst, next_index);
                } else {
                    const next_op = blk: {
                        if (traverse.stack.items.len > 0) {
                            var ti: usize = traverse.stack.items.len - 1;
                            while (ti >= 0) : (ti -= 1) {
                                const item = traverse.stack.items[ti];
                                if (item.state != .post_order and item.state != .middle) {
                                    break :blk item.op;
                                }
                                if (ti == 0) break;
                            }
                        }
                        break :blk leaf.op orelse .@"or";
                    };
                    const jump_on_false = next_op == .@"and";
                    if (jump_on_false) {
                        // The default behavior for comparison instructions is to jump on true. So to jump on false, we negate the instruction.
                        self.negate(inst);
                    }

                    var si: i32 = @as(i32, @intCast(traverse.stack.items.len)) - 2;
                    const next_jump: ?ExpressionTraversal.StackItem = blk: {
                        while (si >= 0) : (si -= 1) {
                            const item = traverse.stack.items[@as(usize, @intCast(si))];
                            if (item.state == .post_order or item.state == .middle) continue;
                            if (jump_on_false) {
                                if (item.op == .@"or") {
                                    break :blk item;
                                }
                            } else {
                                if (item.op == .@"and") {
                                    break :blk item;
                                }
                            }
                        }
                        break :blk null;
                    };
                    if (next_jump) |stack_item| {
                        try unresolved.append(self.gpa, .{ .li = li, .idx = stack_item.index });
                    } else {
                        self.replaceJump(inst, if (jump_on_false) next_index else columns_start);
                    }
                }
            }
        }
        debug("unresolved len: {d}, items: {any}", .{ unresolved.items.len, unresolved.items });
        assert(unresolved.items.len == 0);
    }

    fn hasColumnInExpression(pre_result: []PreResult, index: InternPool.Index.Optional) bool {
        for (pre_result) |item| {
            if (item.index == index) {
                return item.has_col;
            }
        }
        return false;
    }

    const PreResult = struct { index: InternPool.Index.Optional, has_col: bool };
    fn wherePreTraversal(self: *InstGen, select: *const SelectStmt) Error![]PreResult {
        var result_list: std.ArrayListUnmanaged(PreResult) = .{};

        var list: std.ArrayListUnmanaged(struct { index: InternPool.Index.Optional, visited: enum { no, left, yes } }) = .{};
        defer list.deinit(self.gpa);

        try list.append(self.gpa, .{ .index = select.where, .visited = .no });

        blk: while (list.items.len != 0) {
            const idx_visit = &list.items[list.items.len - 1];
            const index = idx_visit.index;
            if (index == .none) {
                _ = list.pop();
                continue;
            }
            const key = self.ip.indexToKey(index.unwrap().?).expression;

            if (idx_visit.visited == .yes) {
                _ = list.pop();
                continue;
            }

            for (0..2) |i| {
                const term: InternPool.Term = if (i == 0) key.lhs else key.rhs;
                const is_lhs: bool = i == 0;
                if (is_lhs and idx_visit.visited == .left) continue;
                switch (term) {
                    .expression => |expr| {
                        if (is_lhs) {
                            idx_visit.* = .{ .index = index, .visited = .left };
                        } else {
                            idx_visit.* = .{ .index = index, .visited = .yes };
                        }
                        // Append has to be after pointer usage to prevent using an 'expired' pointer
                        try list.append(self.gpa, .{ .index = expr, .visited = .no });
                        continue :blk;
                    },
                    .column => {
                        for_blk: for (list.items) |item| {
                            if (item.visited != .no or item.index == index) {
                                for (result_list.items) |result| {
                                    if (result.index == item.index) break :for_blk;
                                }
                                try result_list.append(self.gpa, .{ .index = item.index, .has_col = true });
                            }
                        }
                    },
                    else => {},
                }
            }
            _ = list.pop();
        }

        return result_list.toOwnedSlice(self.gpa);
    }

    // This method traverses the where clause and generates instructions for it.
    // There are 2 passes - 1 to fill in the values in the column loop, and another to populate the constants
    // In the future there could be multiple loops to fill
    pub fn whereTraversal(
        self: *InstGen,
        comptime col_pass: bool,
        cursor: InternPool.Index,
        halt_index: InternPool.InstIndex, // Only on the constant pass
        cursor_move_index: InternPool.InstIndex.Marked,
        labels: *LabelList,
        current_reg: Register.Index,
        select: *const SelectStmt,
    ) Error!struct {
        seek_optimization: SeekOptimization,
        columns_start: InternPool.InstIndex,
        reg_count: Register.Index,
    } {
        if (select.where == .none) {
            return .{ .seek_optimization = .none, .columns_start = self.ip.peekInst(), .reg_count = .first };
        }
        // TODO: share this outside of the method
        var seek_optimization: SeekOptimization = .none;

        var primary_key_col: InternPool.Index.Optional = .none;

        const compare_reg = Register.Index.first;
        var reg_count = current_reg;
        var columns_start = self.ip.peekInst();

        var traversal = try ExpressionTraversal.init(self.ip, select.where);
        defer traversal.deinit(self.gpa);

        var register_stack: std.ArrayListUnmanaged(Register.Index) = .{};
        defer register_stack.deinit(self.gpa);

        // TODO: tree traversal left and right side. When the left side is the id record (ge/gt) with and, then its seek loop for ea one
        // we also want to pay attention to the pop node, which happens between the left and right side
        // good news: the pop is provided with the RHS value. So we compute the instruction for the RHS, then we do the pop
        // and then we ignore the operator, since the pop covers that
        var rhs_expr: bool = false;
        var new_reg_stack_added: bool = false;

        while (try traversal.next(self.gpa)) |leaf| {
            const expr_idx_opt = leaf.index;
            if (expr_idx_opt == .none) {
                continue;
            }
            const op = leaf.op;
            var prev_expr: ?InternPool.Expression = null;
            var is_seek_expr: bool = false;
            const expr = self.ip.indexToKey(expr_idx_opt.unwrap().?).expression;
            debug("col_pass: {}, traversal leaf: {}, expr: {}", .{ col_pass, leaf, expr });

            const first_inst = self.ip.peekInst();

            // Expression traversal can return expression result with expression term on each side
            // It will do so in-order, and then post-order. We can use the in-order node output to signal
            // the end of the LHS and beginning of the right. Useful for math terms.
            // We can use the post-order node output as the time to add the comparison instruction.
            // In this case, we want to ignore and or expression output.
            const is_both_expr = expr.lhs.tag() == .expression and expr.rhs.tag() == .expression;
            if (is_both_expr) {
                if (expr.operator.isComparison()) {
                    if (leaf.state == .in_order) {
                        try register_stack.append(self.gpa, reg_count);
                        new_reg_stack_added = true;
                        reg_count = reg_count.increment();
                    } else {
                        // TODO: Validate that this doesn't panic with a weird input
                        const rhs_reg = register_stack.pop();
                        const lhs_reg = register_stack.pop();
                        if (!col_pass) continue;
                        try labels.append(self.gpa, .{
                            .jump = first_inst,
                            .inst = self.ip.peekInst(),
                            .expr_index = expr_idx_opt,
                        });
                        switch (expr.operator) {
                            .eq => {
                                _ = try self.addInst(.{ .eq = .{
                                    .lhs_reg = lhs_reg,
                                    .rhs_reg = rhs_reg,
                                    .jump = .none,
                                } });
                            },
                            .ne => {
                                _ = try self.addInst(.{ .neq = .{
                                    .lhs_reg = lhs_reg,
                                    .rhs_reg = rhs_reg,
                                    .jump = .none,
                                } });
                            },
                            .gt, .gte, .lt, .lte => {
                                const data: InternPool.Instruction.Lt = .{
                                    .lhs_reg = lhs_reg,
                                    .rhs_reg = rhs_reg,
                                    .jump = .none,
                                };
                                switch (expr.operator) {
                                    .gt => _ = try self.addInst(.{ .gt = data }),
                                    .gte => _ = try self.addInst(.{ .gte = data }),
                                    .lt => _ = try self.addInst(.{ .lt = data }),
                                    .lte => _ = try self.addInst(.{ .lte = data }),
                                    else => unreachable,
                                }
                            },
                            else => unreachable,
                        }
                    }
                }
                continue;
            } else if (leaf.state == .post_order) {
                continue;
            }

            // Check for capable seek optimization. For seek optimization, the loop will start at the set index instead of at 0.
            for (0..2) |i| {
                const is_lhs: bool = i == 0;
                const term = if (is_lhs) expr.lhs else expr.rhs;
                const other_term = if (is_lhs) expr.rhs else expr.lhs;
                switch (term) {
                    .column => |col_idx| {
                        const col = self.ip.indexToKey(col_idx.unwrap().?).column;
                        if (col.is_primary_key and col.tag == .integer and seek_optimization == .none) {
                            primary_key_col = term.column;
                            // TODO: support math operations on other term
                            if (op == null or (op == .@"and" and traversal.isValidSeekOptimization()) and other_term.tag() == .int) {
                                if (is_lhs) {
                                    switch (expr.operator) {
                                        .gt => seek_optimization = .gt,
                                        .gte => seek_optimization = .ge,
                                        else => {},
                                    }
                                } else {
                                    switch (expr.operator) {
                                        .lt => seek_optimization = .gt,
                                        .lte => seek_optimization = .ge,
                                        else => {},
                                    }
                                }
                            }
                            if (seek_optimization != .none) {
                                is_seek_expr = true;
                                break;
                            }
                        }
                    },
                    else => {},
                }
            }

            // Add instructions
            for (0..2) |i| {
                const is_lhs: bool = i == 0;
                const term = if (is_lhs) expr.lhs else expr.rhs;
                const other_term = if (is_lhs) expr.rhs else expr.lhs;
                const col_opt: ?InternPool.Column = blk: {
                    switch (term) {
                        .column => |col_idx_opt| {
                            break :blk self.ip.indexToKey(col_idx_opt.unwrap().?).column;
                        },
                        else => {},
                    }
                    break :blk null;
                };
                switch (term) {
                    .column => if (col_opt) |col| {
                        const col_reg: Register.Index = blk: {
                            if (!is_lhs and other_term.tag() == .column and !expr.operator.isAndOr() and !expr.operator.isMath()) {
                                reg_count = reg_count.increment();
                                break :blk reg_count.decrement();
                            }
                            if (expr.operator.isMath()) {
                                reg_count = reg_count.increment();
                                break :blk reg_count.decrement();
                            }
                            if (expr.operator == .like and is_lhs) {
                                reg_count = reg_count.increment();
                                reg_count = reg_count.increment();
                                break :blk reg_count.decrement();
                            }
                            break :blk compare_reg;
                        };
                        debug("column: {}, {}", .{ col, expr });
                        if (col_pass) {
                            if (col.is_primary_key and col.tag == .integer) {
                                _ = try self.addInst(.{ .row_id = .{
                                    .read_cursor = cursor,
                                    .store_reg = col_reg,
                                } });
                            } else {
                                _ = try self.addInst(.{ .column = .{
                                    .cursor = cursor,
                                    .store_reg = col_reg,
                                    .col = term.column.unwrap().?,
                                } });
                            }
                            if (is_lhs and expr.operator.isAndOr() and !other_term.isConstant()) {
                                try labels.append(self.gpa, .{
                                    .jump = first_inst,
                                    .inst = self.ip.peekInst(),
                                    .expr_index = expr_idx_opt,
                                });
                                _ = try self.addInst(.{ .@"if" = .{ .compare_reg = compare_reg, .jump_address = .none } });
                            }
                        }
                    },
                    .string => {
                        if (!col_pass) {
                            _ = try self.addInst(.{ .string = .{
                                .string = term.string,
                                .store_reg = if (expr.operator == .like) reg_count.decrement().decrement() else reg_count,
                            } });
                        }
                        reg_count = reg_count.increment();
                    },
                    .int => {
                        if (!col_pass) {
                            if (is_seek_expr) {
                                _ = try self.addInst(.{ .integer = .{ .int = term.int, .store_reg = reg_count } });
                                const seek: InternPool.Instruction.Seek = .{
                                    .table = select.table,
                                    .seek_key = reg_count,
                                    .end_inst = halt_index,
                                };
                                _ = try self.ip.replaceInst(self.gpa, cursor_move_index, switch (seek_optimization) {
                                    .gt => .{ .seek_gt = seek },
                                    .ge => .{ .seek_ge = seek },
                                    else => unreachable,
                                });
                                seek_optimization = .used;
                            } else {
                                debug("int inst: {d}", .{self.ip.peekInst()});
                                _ = try self.addInst(.{ .integer = .{ .int = term.int, .store_reg = reg_count } });
                            }
                        }
                        reg_count = reg_count.increment();
                    },
                    .expression => |expr_index| {
                        if (!is_lhs and expr_index != .none and !expr.operator.isAndOr()) {
                            rhs_expr = true;
                            prev_expr = expr;
                        }
                    },
                    else => {},
                }
                if (is_seek_expr) continue;
                if (is_lhs and (rhs_expr or (term.isConstant() and expr.operator.isAndOr())) or !is_lhs and !rhs_expr) {
                    const cur_expr = if (rhs_expr) if (prev_expr) |prev| prev else expr else expr;
                    const cur_op = cur_expr.operator;
                    var new_math_reg: bool = false;
                    rhs_expr = false;
                    debug("cur_op: {}, cur_expr: {}", .{ cur_op, cur_expr });
                    // TODO: create a trailing variable to say if all are static than they can go in the col_pass. Currently, all are in the loop
                    // if (!col_pass) continue;
                    switch (cur_op) {
                        .add, .minus, .multiply, .divide, .remainder => {
                            const last_item_reg = reg_count.decrement();
                            if (register_stack.items.len == 0) {
                                try register_stack.append(self.gpa, reg_count);
                                new_math_reg = true;
                                reg_count = reg_count.increment();
                            }
                            if (!col_pass) continue;
                            const math_reg: Register.Index = register_stack.items[register_stack.items.len - 1];
                            const lhs_reg = blk: {
                                if (new_reg_stack_added) {
                                    new_reg_stack_added = false;
                                    break :blk math_reg.increment();
                                }
                                if (new_math_reg) {
                                    new_math_reg = false;
                                    break :blk last_item_reg.decrement();
                                }
                                break :blk math_reg;
                            };
                            switch (cur_op) {
                                .add => _ = try self.addInst(.{ .add = .{
                                    .lhs_reg = lhs_reg,
                                    .rhs_reg = last_item_reg,
                                    .result_reg = math_reg,
                                } }),
                                .minus => _ = try self.addInst(.{ .subtract = .{
                                    .lhs_reg = lhs_reg,
                                    .rhs_reg = last_item_reg,
                                    .result_reg = math_reg,
                                } }),
                                .multiply => _ = try self.addInst(.{ .multiply = .{
                                    .lhs_reg = lhs_reg,
                                    .rhs_reg = last_item_reg,
                                    .result_reg = math_reg,
                                } }),
                                .divide => _ = try self.addInst(.{ .divide = .{
                                    .lhs_reg = lhs_reg,
                                    .rhs_reg = last_item_reg,
                                    .result_reg = math_reg,
                                } }),
                                .remainder => _ = try self.addInst(.{ .remainder = .{
                                    .lhs_reg = lhs_reg,
                                    .rhs_reg = last_item_reg,
                                    .result_reg = math_reg,
                                } }),
                                else => unreachable, // TODO: implement
                            }
                        },
                        else => {
                            if (col_pass) {
                                try labels.append(self.gpa, .{
                                    .jump = first_inst,
                                    .inst = switch (cur_op) {
                                        .like => self.ip.peekInst().increment(),
                                        else => self.ip.peekInst(),
                                    },
                                    .expr_index = expr_idx_opt,
                                });
                                var cur_reg = reg_count.decrement();
                                const check_reg = blk: {
                                    if (term.isConstant() and other_term.isConstant()) break :blk cur_reg.decrement();
                                    if (register_stack.items.len > 0) break :blk register_stack.pop();
                                    break :blk compare_reg;
                                };
                                if (check_reg != compare_reg and expr.rhs.tag() == .column) {
                                    cur_reg = compare_reg;
                                }
                                switch (cur_op) {
                                    .eq => {
                                        _ = try self.addInst(.{ .eq = .{
                                            .lhs_reg = check_reg,
                                            .rhs_reg = cur_reg,
                                            .jump = .none,
                                        } });
                                    },
                                    .ne => {
                                        _ = try self.addInst(.{ .neq = .{
                                            .lhs_reg = check_reg,
                                            .rhs_reg = cur_reg,
                                            .jump = .none,
                                        } });
                                    },
                                    .gt, .gte, .lt, .lte => {
                                        const data: InternPool.Instruction.Lt = .{
                                            .lhs_reg = check_reg,
                                            .rhs_reg = cur_reg,
                                            .jump = .none,
                                        };
                                        const col_lhs = expr.rhs.tag() != .column or expr.lhs.tag() == .expression;
                                        switch (cur_op) {
                                            // TODO: handle behaviour when both sides are not column
                                            .gt => _ = try self.addInst(if (col_lhs) .{ .gt = data } else .{ .lt = data }),
                                            .gte => _ = try self.addInst(if (col_lhs) .{ .gte = data } else .{ .lte = data }),
                                            .lt => _ = try self.addInst(if (col_lhs) .{ .lt = data } else .{ .gt = data }),
                                            .lte => _ = try self.addInst(if (col_lhs) .{ .lte = data } else .{ .gte = data }),
                                            else => unreachable,
                                        }
                                    },
                                    .like => {
                                        _ = try self.addInst(.{
                                            .function = .{
                                                .index = BuiltInFunctionIndex.like,
                                                // Like has 2 arguments
                                                .first_argument_register = cur_reg.decrement().decrement(),
                                                .result_register = compare_reg,
                                            },
                                        });
                                        _ = try self.addInst(.{ .@"if" = .{ .compare_reg = compare_reg, .jump_address = .none } });
                                    },
                                    .unary, .@"and", .@"or" => {
                                        debug("unary, and, or: {}", .{expr});
                                        _ = try self.addInst(.{ .@"if" = .{ .compare_reg = if (term.isConstant()) cur_reg else check_reg, .jump_address = .none } });
                                    },
                                    else => unreachable,
                                }
                            }
                        },
                    }
                }
            }
        } else {
            columns_start = self.ip.peekInst();
        }
        return .{
            .seek_optimization = seek_optimization,
            .columns_start = columns_start,
            // reg_count is first available to use register.
            .reg_count = reg_count,
        };
    }

    // This function generates the instructions to be executed by the VM
    // The instructions are based off SQLite: https://www.sqlite.org/opcode.html
    // However, some behaviour is not fully supported.
    // In addition, there's no concept of P1 - P5. Instead, all instructions have a dynamic number of 4 byte fields.
    // There are multiple passes through the WHERE expression clause to define the column and constant values into registers
    pub fn buildInstructions(self: *InstGen) Error!void {
        switch (self.statement) {
            Stmt.select => {
                const select = self.statement.select;
                const table = self.ip.indexToKey(select.table).table;
                debug("page_index: {d}", .{table.page});

                const cursor = try self.ip.put(self.gpa, .{ .cursor = .{ .index = 0 } });

                const init_index = try self.addInst(.{ .init = InternPool.InstIndex.none });
                const open_read_index = try self.addInst(.{ .open_read = select.table });

                // rewind or SeekGT / LT / GE / LE
                const cursor_move_index = try self.ip.markInst(self.gpa);
                const loop_start = self.ip.peekInst();

                const where_clause = select.where;
                debug("Where: {}", .{where_clause});
                var labels: LabelList = .{};
                defer labels.deinit(self.gpa);

                // const pre_result = try self.wherePreTraversal(&select);

                // Column Loop and pass through of the where expression tree
                // Jump locations are left empty until we know all instruction addresses, since we don't know where to jump to yet.
                const where_result = try self.whereTraversal(
                    true,
                    cursor,
                    .none,
                    cursor_move_index,
                    &labels,
                    Register.Index.first.increment(),
                    &select,
                );
                const seek_optimization = where_result.seek_optimization;
                const columns_start = where_result.columns_start;
                const reg_count = where_result.reg_count;

                const first_output = if (reg_count == .first) reg_count.increment() else reg_count;
                var output_count = first_output;
                var cur_col = select.columns;

                debug("cur_col", .{});

                // Column output pass - Load the registers with the results as defined by result_column (i.e. SELECT <result_column> FROM ...)
                // TODO: We will need to split this into 2 passes, one for constants and one for columns
                while (cur_col.unwrap()) |col_idx| {
                    const res_col = self.ip.indexToKey(col_idx).result_column;
                    switch (res_col.val) {
                        .wildcard => {
                            var reader = TableMetadataReader.from(self.ip, select.table);
                            while (reader.next()) |col_res| {
                                const col = col_res.col;
                                try self.addColumnInst(col_res.index, col, cursor, output_count);
                                output_count = output_count.increment();
                            }
                        },
                        .expr_alias => |val| {
                            debug("expr_alias: {}", .{val});
                            const expr_idx_opt = val.expr;
                            assert(expr_idx_opt != .none);
                            const expr = self.ip.indexToKey(expr_idx_opt.unwrap().?).expression;
                            switch (expr.operator) {
                                .unary => {
                                    switch (expr.lhs) {
                                        .column => |expr_col_idx| {
                                            const col = self.ip.indexToKey(expr_col_idx.unwrap().?).column;
                                            debug("inst column: {}", .{col});
                                            try self.addColumnInst(expr_col_idx.unwrap().?, col, cursor, output_count);
                                            output_count = output_count.increment();
                                        },
                                        else => unreachable, // TODO: implement
                                    }
                                },
                                else => {
                                    var traversal = try ExpressionTraversal.init(self.ip, expr_idx_opt);
                                    while (try traversal.next(self.gpa)) |leaf| {
                                        // TODO: implement
                                        _ = leaf;
                                        unreachable;
                                    }
                                },
                            }
                        },
                        else => unreachable, // TODO: implement table wildcard
                    }
                    cur_col = res_col.next_col;
                }
                debug("columns: {b}", .{select.columns});

                debug("output count: {d}", .{output_count});
                _ = try self.addInst(.{ .result_row = .{
                    .start_reg = first_output,
                    .end_reg = output_count,
                } });
                const next_index = try self.addInst(.{ .next = .{ .cursor = cursor, .success_jump = loop_start } });
                const halt_index = try self.addInst(InternPool.Instruction.halt);
                // TODO: support multiples databases, writing to tables
                const transaction_index = try self.addInst(.{ .transaction = .{ .database_id = 0, .write = false } });

                try self.fillLabels(labels, where_clause, next_index, columns_start);

                debug("second pass", .{});

                // TODO: implement fillLabels with constant comparisons
                var labels_constants: LabelList = .{};
                defer labels_constants.deinit(self.gpa);

                // Second pass of the WHERE expression, this pass we can fill in the constants outside of the column loop
                // to prevent unneccessary register loads
                _ = try self.whereTraversal(
                    false,
                    cursor,
                    halt_index,
                    cursor_move_index,
                    &labels,
                    Register.Index.first.increment(),
                    &select,
                );

                try self.fillLabels(labels_constants, where_clause, halt_index, loop_start);

                _ = try self.addInst(.{ .goto = open_read_index });
                self.ip.setInst(init_index, .{ .init = transaction_index });
                if (seek_optimization == .none) {
                    _ = try self.ip.replaceInst(self.gpa, cursor_move_index, .{ .rewind = .{ .table = select.table, .end_inst = halt_index } });
                }
                debug("instructions written", .{});
            },
        }
    }
};

// All registers are the same size, so its possible to update register type without allocating more data
// this would not be true on a 64 bit system, since the slice will be 128 bits.
// In SQLite, max page size is 2^48. So we can do a 48 bit ptr and 16 bit length. But then max compare length is 2^16.
const Register = union(enum) {
    none,
    int: i64,
    float: f64,
    string: StringLen,
    str: []u8, // TODO: consider removing these, and make all bytes be interned. Or use a 32 bit index instead of a slice
    binary: []u8,
    // TODO: We can refer to DB file bytes using a 64 bit value - 48 bits for the page number and 16 bits for the offset within the page
    // This works because max number of pages is 2^48 and max page size is 2^16 in SQLite
    // We then also need to have additional parsing since table values can overflow to overflow pages

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
                .none => .none,
                else => @enumFromInt(@intFromEnum(self) + 1),
            };
        }

        pub fn decrement(self: Index) Index {
            return switch (self) {
                .first => .first,
                .none => .none,
                else => @enumFromInt(@intFromEnum(self) - 1),
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
                .str => std.mem.eql(u8, self.str, other.str),
                .string => std.mem.eql(u8, self.string.string.slice(self.string.len, ip), other.string.string.slice(self.string.len, ip)),
                .binary => unreachable, // TODO: implement
            };
        } else if (self.tag() == .string and other.tag() == .str) {
            return std.mem.eql(u8, self.string.string.slice(self.string.len, ip), other.str);
        } else if (self.tag() == .str and other.tag() == .string) {
            return std.mem.eql(u8, self.str, other.string.string.slice(other.string.len, ip));
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

pub inline fn char_lower(char: u8) u8 {
    return switch (char) {
        'A'...'Z' => char | 0x20, // convert to lowercase by setting the 6th bit
        else => char,
    };
}

// TODO: figure out why '%_' is so slow to match and speed it up
// Create fast paths for %abc%, %abc, abc%
fn like(str: []u8, pattern: []u8) bool {
    var si: u32 = 0;
    var pi: u32 = 0;
    var wild_char: u32 = 0;
    while (si < str.len and pi < pattern.len) {
        switch (pattern[pi]) {
            '%' => {
                while (pi + 1 < pattern.len and pi == '%') : (pi += 1) {}
                if (pi + 1 == pattern.len) return true;
                wild_char = pi + 1;
                if (pattern[pi + 1] != '_') {
                    while (si < str.len and char_lower(str[si]) != char_lower(pattern[pi + 1])) : (si += 1) {}
                }
                pi += 1;
            },
            '_' => {
                if (si + 1 == str.len) return true;
                if (pi + 1 == pattern.len) {
                    if (wild_char != 0) {
                        pi = wild_char - 1;
                    } else {
                        return false;
                    }
                }
                si += 1;
                pi += 1;
            },
            else => {
                const is_end_mismatch: bool = str.len - si > 1 and pi == pattern.len - 1;
                const is_char_mismatch: bool = char_lower(str[si]) != char_lower(pattern[pi]);
                if (is_end_mismatch or is_char_mismatch) {
                    if (wild_char != 0) {
                        if (pattern[wild_char] == '_') {
                            si += 1;
                            pi = wild_char;
                        } else {
                            if (!is_char_mismatch) {
                                si += 1;
                            }
                            while (si < str.len and char_lower(str[si]) != char_lower(pattern[wild_char])) : (si += 1) {}
                            pi = wild_char;
                        }
                    } else {
                        return false;
                    }
                } else {
                    si += 1;
                    pi += 1;
                    if (si == str.len and pi == pattern.len) return true;
                    if (pi == pattern.len) return false;
                }
            },
        }
    }
    return false;
}

const FunctionContext = struct {
    ip: *InternPool,
    vm: *Vm,
    first_reg: Register.Index,
    return_reg: Register.Index,
};

fn like_func(ctx: FunctionContext, args: u8) anyerror!void {
    if (args != 2) return;
    const ip = ctx.ip;
    const vm = ctx.vm;
    const pattern_reg = vm.reg(ctx.first_reg);
    const string_reg = vm.reg(ctx.first_reg.increment());
    const pattern: []u8 = switch (pattern_reg) {
        .str => |reg_str| reg_str,
        .string => |reg_string| @constCast(reg_string.string.slice(reg_string.len, ip)),
        else => unreachable,
    };
    const string: []u8 = switch (string_reg) {
        .str => |reg_str| reg_str,
        .string => |reg_string| @constCast(reg_string.string.slice(reg_string.len, ip)),
        else => unreachable,
    };
    if (like(string, pattern)) {
        try vm.updateReg(ctx.return_reg, .{ .int = 1 });
    } else {
        try vm.updateReg(ctx.return_reg, .{ .int = 0 });
    }
}

const BuiltInFunction = *const fn (ctx: FunctionContext, args: u8) anyerror!void;

// TODO: we can make this code comptime so the enum and array are automatically populated
const builtin_funcs = [_]BuiltInFunction{like_func};
const builtin_funcs_args = [_]u8{2};
const BuiltInFunctionIndex = enum(u32) {
    like,

    pub fn unwrap(self: BuiltInFunctionIndex) u32 {
        return @intFromEnum(self);
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
            debug("updateReg: index_num: {d}, len: {d}, item: {}", .{ index_num, self.reg_list.len, item });
            self.reg_list.set(index_num, item);
        }
    }

    pub fn exec(self: *Vm) Error!void {
        var instruction: InternPool.Instruction = self.ip.getInst(self.pc).?;
        // TODO: multiple cursors
        // TODO: clean up these variables
        var record: ?SQLiteRecord = null;
        var col_count: u32 = 0;
        var cell_count: u32 = 0; // cursor
        var col_value: ?SQLiteColumn = null;
        var table_root_page_index: u32 = 0;

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
                    table_root_page_index = table.page;
                    record = self.db.getRecord(table_root_page_index, 0);
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
                    debug("col_value: {?}", .{col_value});
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
                    // var write_buf: [256]u8 = undefined;
                    var row_buf: [512]u8 = undefined;
                    var row_buf_written: u32 = 4;
                    // var write_count: u8 = 0;
                    row_buf[0..4].* = std.mem.toBytes(len);
                    while (i < end_reg_num) : (i += 1) {
                        const cur_reg = self.reg(@enumFromInt(i));
                        // const written = cur_reg.toStr(@constCast(write_buf[write_count..]), self.ip) catch write_buf[write_count..];
                        const written_row = cur_reg.toBuf(row_buf[row_buf_written..], self.ip) catch row_buf[row_buf_written..];
                        row_buf_written += written_row.len;
                        // const written_len: u8 = @intCast(written.len);
                        // debug("written len: {d}", .{written_len});
                        // write_count += written_len;
                        // if (i != end_reg_num - 1) {
                        //     write_buf[write_count] = '|';
                        //     write_count += 1;
                        // }
                    }
                    // print(write_buf[0..write_count].ptr, write_buf[0..write_count].len);
                    renderRow(row_buf[0..row_buf_written].ptr, row_buf[0..row_buf_written].len);
                    self.pc = self.pc.increment();
                },
                .function => |function_data| {
                    const index = function_data.index;
                    const func = builtin_funcs[index.unwrap()];
                    const arg_count = builtin_funcs_args[index.unwrap()];
                    const context: FunctionContext = .{
                        .ip = self.ip,
                        .vm = self,
                        .first_reg = function_data.first_argument_register,
                        .return_reg = function_data.result_register,
                    };
                    // TODO: better error return handling
                    func(context, arg_count) catch return error.OutOfMemory;
                    self.pc = self.pc.increment();
                },
                .seek_gt, .seek_ge => |seek_data| {
                    const end_inst = seek_data.end_inst;
                    const reg_cmp = seek_data.seek_key;
                    cell_count = @intCast(self.reg(reg_cmp).int);
                    if (instruction == .seek_ge) {
                        cell_count -= 1;
                    }
                    record = self.db.getRecord(table_root_page_index, cell_count);
                    if (record == null) {
                        self.pc = end_inst;
                    } else {
                        col_value = record.?.next();
                        col_count += 1;
                        self.pc = self.pc.increment();
                    }
                },
                .gt, .gte, .lt, .lte => |lt_data| {
                    const jump_address = lt_data.jump;
                    const lhs_reg_index = lt_data.lhs_reg;
                    const rhs_reg_index = lt_data.rhs_reg;
                    const lhs_reg = self.reg(lhs_reg_index);
                    const rhs_reg = self.reg(rhs_reg_index);
                    if (lhs_reg.tag() != .int or rhs_reg.tag() != .int) {
                        // TODO: support coersion
                        debug("LT comparison. lhs: {}, rhs: {}", .{ lhs_reg, rhs_reg });
                        return Error.InvalidSyntax;
                    }
                    if (switch (instruction) {
                        .gt => lhs_reg.int > rhs_reg.int,
                        .gte => lhs_reg.int >= rhs_reg.int,
                        .lt => lhs_reg.int < rhs_reg.int,
                        .lte => lhs_reg.int <= rhs_reg.int,
                        else => false,
                    }) {
                        self.pc = jump_address;
                    } else {
                        self.pc = self.pc.increment();
                    }
                },
                .@"if", .if_not => |if_data| {
                    const jump_address = if_data.jump_address;
                    const if_reg_index = if_data.compare_reg;
                    const if_reg = self.reg(if_reg_index);

                    const is_if: bool = switch (instruction) {
                        .@"if" => true,
                        else => false,
                    };

                    const is_true = switch (if_reg) {
                        .int => |val| val != 0,
                        .float => |val| val != 0.0,
                        .string => |val| (std.fmt.parseInt(i64, val.string.slice(val.len, self.ip), 10) catch 0) != 0,
                        .str => |val| (std.fmt.parseInt(i64, val, 10) catch 0) != 0, // TODO: support float coersion
                        else => false, // TODO: check if blob can be evaluated to true
                    };

                    if (is_true) {
                        if (is_if) {
                            self.pc = jump_address;
                        } else {
                            self.pc = self.pc.increment();
                        }
                    } else {
                        if (is_if) {
                            self.pc = self.pc.increment();
                        } else {
                            self.pc = jump_address;
                        }
                    }
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

                    debug("EQ comparison. lhs: {}, rhs: {}", .{ lhs_reg, rhs_reg });

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
                    cell_count += 1;
                    record = self.db.getRecord(table_root_page_index, cell_count);
                    if (record == null) {
                        self.pc = self.pc.increment();
                    } else {
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
                .add => |inst| {
                    const lhs = self.reg(inst.lhs_reg);
                    const rhs = self.reg(inst.rhs_reg);
                    // TODO: cover other types for addition
                    if (lhs.tag() == .int and rhs.tag() == .int) {
                        const result: i64 = lhs.int + rhs.int;
                        try self.updateReg(inst.result_reg, .{ .int = result });
                    }
                    self.pc = self.pc.increment();
                },
                .subtract => |inst| {
                    const lhs = self.reg(inst.lhs_reg);
                    const rhs = self.reg(inst.rhs_reg);
                    // TODO: cover other types
                    if (lhs.tag() == .int and rhs.tag() == .int) {
                        const result: i64 = lhs.int - rhs.int;
                        try self.updateReg(inst.result_reg, .{ .int = result });
                    }
                    self.pc = self.pc.increment();
                },
                .multiply => |inst| {
                    const lhs = self.reg(inst.lhs_reg);
                    const rhs = self.reg(inst.rhs_reg);
                    // TODO: cover other types
                    if (lhs.tag() == .int and rhs.tag() == .int) {
                        const result: i64 = lhs.int * rhs.int;
                        try self.updateReg(inst.result_reg, .{ .int = result });
                    }
                    self.pc = self.pc.increment();
                },
                .divide => |inst| {
                    const lhs = self.reg(inst.lhs_reg);
                    const rhs = self.reg(inst.rhs_reg);
                    // TODO: cover other types
                    if (lhs.tag() == .int and rhs.tag() == .int) {
                        if (rhs.int == 0) {
                            try self.updateReg(inst.result_reg, .none);
                        }
                        const result: i64 = @divTrunc(lhs.int, rhs.int);
                        try self.updateReg(inst.result_reg, .{ .int = result });
                    }
                    self.pc = self.pc.increment();
                },
                .remainder => |inst| {
                    const lhs = self.reg(inst.lhs_reg);
                    const rhs = self.reg(inst.rhs_reg);
                    // TODO: cover other types
                    if (lhs.tag() == .int and rhs.tag() == .int) {
                        if (rhs.int == 0) {
                            try self.updateReg(inst.result_reg, .none);
                        }
                        const den = if (rhs.int < 0) -rhs.int else rhs.int;
                        const result: i64 = @rem(lhs.int, den);
                        try self.updateReg(inst.result_reg, .{ .int = result });
                    }
                    self.pc = self.pc.increment();
                },
                // else => debug("instruction not implemented: {}", .{instruction.opcode}),
            }
        }
    }
};

const MinimizedToken = struct { tag: TokenType, start: u32 };
const TokenList = MultiArrayList(MinimizedToken);

fn parseStatement(str: [:0]u8, db_memory: DbMemory) Error!void {
    var tokenizer = Tokenizer.from(str, 0);
    var fixed_alloc = std.heap.FixedBufferAllocator.init(&memory_buf);

    var tokens = TokenList{};
    defer tokens.deinit(fixed_alloc.allocator());

    var intern_pool = InternPool.init();
    defer intern_pool.deinit(fixed_alloc.allocator());

    try tokenizer.ingest(fixed_alloc.allocator(), &tokens);

    const db = try Db.init(db_memory);

    // ASTGen can allocate more tokens, so we pass the struct instead of the underlying buffer
    var ast = ASTGen.init(fixed_alloc.allocator(), &tokens, &intern_pool, str, db);

    const statement = try ast.buildStatement();
    debug("statement built!", .{});

    var inst_gen = InstGen.init(fixed_alloc.allocator(), &intern_pool, db, .{ .select = statement });

    debug("building instructions", .{});
    try inst_gen.buildInstructions();
    debug("inst generated!", .{});

    inst_gen.dump();

    // temp return to see inst_dump
    // TODO: make this path taken if work 'explain' is used at start of SQL statement
    // if (true) return;
    var vm = Vm.init(fixed_alloc.allocator(), db, &intern_pool);
    try vm.exec();
}

const DbMemory = struct {
    buffer: []u8,
    max_allocated: usize,
};

// Runs the statement at query_buf pointer with the file partially loaded into memory at loaded_file_ptr.
// The memory for the loaded_file_ptr is allocated with the exported malloc() fn.
// By default the max buffer size is loaded into memory. The first 100 bytes is the SQLite DB header size.
// From the SQLite DB header, we can find the page size.
// size is the total allocated memory available to load pages
// TODO: evict least recently used pages from memory if buffer size is smaller than database size and spill to disk
export fn runStatementWithFile(loaded_file_ptr: ?*u8, size: usize) void {
    if (loaded_file_ptr == null) {
        debug("uh oh no pointer", .{});
        return;
    }
    if (size < sqlite_header_size) {
        debug("Memory has to be greater than {d} bytes", .{sqlite_header_size});
        return;
    }

    const array_ptr: [*]u8 = @ptrCast(loaded_file_ptr);
    const slice = array_ptr[0..size];

    const memory: DbMemory = .{ .buffer = slice, .max_allocated = size };

    parseStatement(&query_buf, memory) catch |err| {
        switch (err) {
            Error.InvalidBinary => debug("uh oh stinky binary file", .{}),
            Error.InvalidSyntax => debug("uh oh stinky SQL syntax", .{}),
            Error.OutOfMemory => debug("uh oh allocator ran out of memory", .{}),
            Error.NotImplemented => debug("uh oh fworgot to impwement -><-", .{}),
        }
        return;
    };
}

export fn getStatementAddr() [*]u8 {
    return &query_buf;
}

// export fn free(ptr: *u8) void {
//     const page_allocator = std.heap.page_allocator;
//     page_allocator.free(@as([*]u8, @ptrCast(ptr)));
// }
