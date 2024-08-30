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

pub fn read(self: Self, buff: []u8) !usize {
    return self.conn.data_buffer.read(buff);
}

pub fn close(self: Self) !void {
    try self.flush();
    try self.conn.close();
}

pub fn flush(self: Self) !void {
    try self.conn.flush();
}
