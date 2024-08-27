const std = @import("std");
const log = std.log;
const Connection = @import("connection.zig");

const Self = @This();

conn: *Connection,

pub fn init(conn: *Connection) Self {
    return .{ .conn = conn };
}

pub fn send(self: Self, data: []const u8) !void {
    try self.conn.send(data);
}

pub fn read(self: Self) ![]const u8 {
    return self.conn.data_buffer.read();
}

pub fn close(self: Self) !void {
    try self.conn.close();
}
