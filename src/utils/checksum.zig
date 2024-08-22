const std = @import("std");
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();
const Self = @This();

value: usize = 0,

pub fn addSlice(self: *Self, slice: []const u8) void {
    var window = std.mem.window(u8, slice, 2, 2);
    while (window.next()) |next| {
        var value = std.mem.readInt(u16, @ptrCast(next.ptr), native_endian);
        if (next.len == 1) { // if slice num is odd, pad last byte
            value <<= 8;
        }
        self.addInt(u16, value);
    }
}

pub fn addInt(self: *Self, comptime T: type, int: T) void {
    if (@typeInfo(T) != .Int) @compileError("only int types are allowed");

    self.value += int;
}

pub fn final(self: Self) u16 {
    var checksum: usize = self.value;
    while ((checksum >> 16) != 0) {
        checksum = (checksum & 0xffff) + (checksum >> 16);
    }

    return ~(@as(u16, @intCast(checksum)));
}

test {
    var c = Self{};
    c.addInt(u64, 0);
    try std.testing.expectEqual(0, c.value);

    try std.testing.expectEqual(0xffff, c.final());
    try std.testing.expectEqual(0, (Self{ .value = 0xffff }).final());
}
