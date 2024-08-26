const std = @import("std");

pub fn StreamSource(comptime T: type) type {
    return struct {
        const Self = @This();

        sem: std.Thread.Semaphore = .{},
        data: std.ArrayList(T),
        closed: bool = false,

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{ .data = std.ArrayList(T).init(allocator) };
        }

        pub fn deinit(self: *Self) void {
            self.close();
            self.data.deinit();
        }

        pub fn read(self: *Self) !?T {
            if (self.closed) return null;
            self.sem.wait();
            return self.data.pop();
        }

        pub fn write(self: *Self, data: T) !void {
            if (self.closed) return;
            try self.data.append(data);
            self.sem.post();
        }

        pub fn close(self: *Self) void {
            self.closed = true;
        }
    };
}
