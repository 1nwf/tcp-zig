const std = @import("std");
const log = std.log;
const TunDev = @import("tun/tun.zig");
const Connection = @import("connection.zig");
const Ip4Address = Connection.Ip4Address;

const NetIf = @import("netif.zig");

pub fn main() !void {
    var tun = try TunDev.init("tun0");
    try tun.setIpAddr(try std.net.Address.parseIp("192.168.0.1", 0));
    try tun.setNetMask(try std.net.Address.parseIp("255.255.255.0", 0));
    try tun.setDevUp();
    defer tun.deinit();

    var arena_alloc = std.heap.ArenaAllocator.init(std.heap.page_allocator);

    var netif = NetIf.init(tun.stream(), arena_alloc.allocator());
    var handle = try netif.start();
    defer handle.join();

    var lis = try netif.initListener(800);
    defer lis.deinit();
    _ = try std.Thread.spawn(.{}, connect, .{});

    while (try lis.accept()) |conn| {
        log.info("conn: {}", .{conn.addrs});
        try conn.send("test...");
        try conn.close();
    }
}

pub fn connect() !void {
    std.time.sleep(std.time.ns_per_s * 3);
    const stream = try std.net.tcpConnectToAddress(try std.net.Address.resolveIp("192.168.0.2", 800));
    defer stream.close();

    var buff: [1024]u8 = undefined;
    const n = try stream.read(&buff);
    log.info("({}) got: {s}", .{ n, buff[0..n] });

    std.time.sleep(std.time.ns_per_s * 2);
}

test {
    _ = @import("utils/checksum.zig");
}
