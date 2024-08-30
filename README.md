# tcp-zig

A userspace TCP stack using a tun device. This implementation follows [RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293). Basic data transmission and communication is currently implemented with an easily usable API.

Currently only supported on Linux.

**Examples usage:**

```zig 
const std = @import("std");
const log = std.log;
const TunDev = @import("tun/tun.zig");
const NetIf = @import("netif.zig");

pub fn main() !void {
    // create and initialize tun device
    var tun = try TunDev.init("tun0");
    try tun.setIpAddr("192.168.0.1");
    try tun.setNetMask("255.255.255.0");
    try tun.setDevUp();
    defer tun.deinit();

    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);

    // this the main network interface. it takes a stream that it can read/write tcp/ip packets
    var netif = try NetIf.init(tun.stream(), arena_allocator .allocator());
    var handle = try netif.start();
    defer handle.join();

    // create a listener and bind it to port 800
    var lis = try netif.initListener(800);
    defer lis.deinit();

    while (try lis.accept()) |conn| {
        try conn.send("hello!");
        try conn.flush();

        var buff: [128]u8 = undefined;
        const n = try conn.read(&buff);
        log.info("read: {s}", .{buff[0..n]});
        try conn.close();
    }
}
```
