const std = @import("std");
const log = std.log;
const linux = std.os.linux;
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("linux/ioctl.h");
    @cInclude("linux/sockios.h");
    @cInclude("linux/if.h");
    @cInclude("linux/if_tun.h");
});

const Self = @This();

dev: std.fs.File,
name: []const u8,
sock_fd: linux.fd_t,

pub fn init(name: []const u8) !Self {
    if (name.len > linux.IFNAMESIZE) return error.NameTooLong;
    const file = try std.fs.openFileAbsolute("/dev/net/tun", .{ .mode = .read_write });

    var ifreq = linux.ifreq{
        .ifrn = .{ .name = @as(*[linux.IFNAMESIZE]u8, @ptrCast(@constCast(name.ptr))).* },
        .ifru = .{ .flags = c.IFF_UP | c.IFF_TUN | c.IFF_NO_PI },
    };

    try ioctl(file.handle, c.TUNSETIFF, @intFromPtr(&ifreq));
    const sock_fd = try std.posix.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);

    return .{ .dev = file, .sock_fd = sock_fd, .name = name };
}

pub fn deinit(self: *Self) void {
    self.dev.close();
    std.posix.close(self.sock_fd);
}

pub fn setIpAddr(self: *Self, addr: []const u8) !void {
    const ipaddr = try std.net.Address.parseIp(addr, 0);
    var ifreq = linux.ifreq{
        .ifrn = .{ .name = @as(*[linux.IFNAMESIZE]u8, @ptrCast(@constCast(self.name.ptr))).* },
        .ifru = .{ .addr = ipaddr.any },
    };
    try ioctl(self.sock_fd, c.SIOCSIFADDR, @intFromPtr(&ifreq));
}

pub fn setNetMask(self: *Self, mask: []const u8) !void {
    const addr = try std.net.Address.parseIp(mask, 0);
    var ifreq = linux.ifreq{
        .ifrn = .{ .name = @as(*[linux.IFNAMESIZE]u8, @ptrCast(@constCast(self.name.ptr))).* },
        .ifru = .{ .netmask = addr.any },
    };
    try ioctl(self.sock_fd, c.SIOCSIFNETMASK, @intFromPtr(&ifreq));
}

pub fn setDevUp(self: *Self) !void {
    var ifreq = linux.ifreq{
        .ifrn = .{ .name = @as(*[linux.IFNAMESIZE]u8, @ptrCast(@constCast(self.name.ptr))).* },
        .ifru = .{ .flags = c.IFF_UP },
    };

    try ioctl(self.sock_fd, c.SIOCSIFFLAGS, @intFromPtr(&ifreq));
}

fn ioctl(fd: linux.fd_t, request: u32, arg: usize) !void {
    const res = linux.ioctl(fd, request, arg);
    switch (linux.E.init(res)) {
        .SUCCESS => {},
        else => |e| {
            std.log.err("{}", .{e});
            return error.IoctlFailed;
        },
    }
}

pub fn stream(self: *Self) std.io.StreamSource {
    return .{ .file = self.dev };
}
