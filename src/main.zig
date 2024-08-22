const std = @import("std");
const log = std.log;

const TunDev = @import("tun.zig");
const proto = @import("protocols/protocols.zig");
const ip = proto.ip;
const TcpHeader = proto.TcpHeader;

pub fn main() !void {
    var tun = try TunDev.init("tun0");
    try tun.setIpAddr(try std.net.Address.parseIp("192.168.0.1", 0));
    try tun.setNetMask(try std.net.Address.parseIp("255.255.255.0", 0));
    try tun.setDevUp();
    defer tun.deinit();

    var buff: [1500]u8 = undefined;

    while (true) {
        const n = try tun.dev.read(&buff);
        const ip_packet = ip.Packet.parse(buff[0..n]);
        if (ip_packet.header.next_level_protocol != .Tcp) continue;

        const tcp_header = TcpHeader.parse(ip_packet.data);
        log.info("{}", .{tcp_header.hdr});
    }
}

test {
    _ = @import("utils/checksum.zig");
}
