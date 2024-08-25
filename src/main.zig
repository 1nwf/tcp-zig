const std = @import("std");
const log = std.log;

const TunDev = @import("tun/tun.zig");
const proto = @import("protocols/protocols.zig");
const ip = proto.ip;
const TcpPacket = proto.TcpPacket;
const Connection = @import("connection.zig");
const Ip4Address = Connection.Ip4Address;

const PacketReader = struct {
    reader: std.io.AnyReader,

    const Packet = struct {
        iph: ip.Header,
        packet: TcpPacket,
    };

    pub fn readPacket(self: *PacketReader) !Packet {
        var buff: [std.mem.page_size]u8 = undefined;
        const n = try self.reader.read(&buff);
        const data = buff[0..n];

        const ip_packet = ip.Packet.parse(data);
        if (ip_packet.header.next_level_protocol != .Tcp) return error.InvalidProtocol;
        const packet = TcpPacket.parse(ip_packet.data);

        return .{
            .iph = ip_packet.header,
            .packet = packet,
        };
    }
};

pub fn main() !void {
    var tun = try TunDev.init("tun0");
    try tun.setIpAddr(try std.net.Address.parseIp("192.168.0.1", 0));
    try tun.setNetMask(try std.net.Address.parseIp("255.255.255.0", 0));
    try tun.setDevUp();
    defer tun.deinit();

    var arena_alloc = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    var connections = std.ArrayList(Connection).init(arena_alloc.allocator());

    log.info("waiting for incoming packets...", .{});
    var reader = tun.dev.reader();
    var packet_reader = PacketReader{ .reader = reader.any() };

    _ = try std.Thread.spawn(.{}, connect, .{});
    var sent = false;

    while (true) {
        const p = packet_reader.readPacket() catch continue;
        const conn: *Connection = blk: {
            // check if we have an open connection
            for (connections.items) |*con| if (con.addrs.local.port == p.packet.hdr.dest_port) break :blk con;
            // add new connection if it does not exist
            try connections.append(Connection.init(.{ .file = tun.dev }, .{
                .local = Ip4Address{ .addr = p.iph.dest_ip, .port = p.packet.hdr.dest_port },
                .remote = Ip4Address{ .addr = p.iph.source_ip, .port = p.packet.hdr.source_port },
            }));
            break :blk &connections.items[connections.items.len - 1];
        };

        conn.handle_packet(p.packet) catch |e| log.info("error: {}", .{e});
        // test sending data and then closing the connection
        if (!sent and conn.state == .established) {
            log.info("closing connection", .{});
            sent = true;
            try conn.send("hello");
            try conn.close();
        }
    }
}

pub fn connect() !void {
    std.time.sleep(std.time.ns_per_s * 3);
    const stream = try std.net.tcpConnectToAddress(try std.net.Address.resolveIp("192.168.0.2", 443));
    defer stream.close();

    var buff: [1024]u8 = undefined;
    const n = try stream.read(&buff);
    log.info("({}) got: {s}", .{ n, buff[0..n] });

    std.time.sleep(std.time.ns_per_s * 2);
}

test {
    _ = @import("utils/checksum.zig");
}
