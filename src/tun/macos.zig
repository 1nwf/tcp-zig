const std = @import("std");
// the ioctl method defined in the stdlib takes a request of type c_int which causes overflow errors.
// the correct type for request on macos is c_ulong
pub extern "c" fn ioctl(fd: std.posix.fd_t, request: c_ulong, ...) c_int;

const Self = @This();
const c = @cImport({
    @cInclude("sys/ioctl.h");
    @cInclude("net/if.h");
    @cInclude("sys/sys_domain.h");
    @cInclude("sys/kern_control.h");
    @cInclude("net/if_utun.h");
});

dev: std.fs.File,
sockfd: std.posix.fd_t,
ifname: [c.IFNAMSIZ]u8,

pub fn init() !Self {
    var info = std.mem.zeroes(c.ctl_info);
    @memcpy(info.ctl_name[0..c.UTUN_CONTROL_NAME.len], c.UTUN_CONTROL_NAME);
    const fd = try std.posix.socket(std.posix.AF.SYSTEM, std.posix.SOCK.DGRAM, c.SYSPROTO_CONTROL);

    try syscallAssert(ioctl(fd, c.CTLIOCGINFO, @intFromPtr(&info)));

    const sock_addr = c.sockaddr_ctl{
        .sc_len = @sizeOf(c.sockaddr_ctl),
        .sc_family = std.posix.AF.SYSTEM,
        .ss_sysaddr = std.posix.AF.SYS_CONTROL,
        .sc_id = info.ctl_id,
        .sc_unit = 0,
    };
    try std.posix.connect(fd, @ptrCast(&sock_addr), @sizeOf(c.sockaddr_ctl));

    var ifname = std.mem.zeroes([c.IFNAMSIZ]u8);
    var len: u32 = @intCast(ifname.len);
    try syscallAssert(std.c.getsockopt(fd, c.SYSPROTO_CONTROL, c.UTUN_OPT_IFNAME, @ptrCast(&ifname), &len));

    const sockfd = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);

    return .{ .dev = std.fs.File{ .handle = fd }, .ifname = ifname, .sockfd = sockfd };
}

pub fn setIpAddr(self: *Self, addr: std.net.Address) !void {
    var ifreq = c.ifreq{
        .ifr_name = self.ifname,
        .ifr_ifru = .{ .ifru_addr = @bitCast(addr.any) },
    };
    try syscallAssert(ioctl(self.sockfd, c.SIOCSIFADDR, @intFromPtr(&ifreq)));
}

pub fn setNetMask(self: *Self, mask: std.net.Address) !void {
    var ifreq = c.ifreq{
        .ifr_name = self.ifname,
        .ifr_ifru = .{ .ifru_addr = @bitCast(mask.any) },
    };
    try syscallAssert(ioctl(self.sockfd, c.SIOCSIFNETMASK, @intFromPtr(&ifreq)));
}

pub fn setDevUp(self: *Self) !void {
    var ifreq = c.ifreq{
        .ifr_name = self.ifname,
        .ifr_ifru = .{ .ifru_flags = c.IFF_UP },
    };

    try syscallAssert(ioctl(self.sockfd, c.SIOCSIFFLAGS, @intFromPtr(&ifreq)));
}

fn syscallAssert(res: c_int) !void {
    switch (std.posix.errno(res)) {
        .SUCCESS => {},
        else => |e| {
            std.log.err("{}", .{e});
            return error.SyscallFailed;
        },
    }
}

test {
    var self = try init();
    try self.setIpAddr(try std.net.Address.parseIp("192.168.20.1", 0));
    try self.setNetMask(try std.net.Address.parseIp("255.255.255.0", 0));
    try self.setDevUp();
}
