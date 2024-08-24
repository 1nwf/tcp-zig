const std = @import("std");
const log = std.log;

const TunDev = @import("tun/tun.zig");
const proto = @import("protocols/protocols.zig");
const ip = proto.ip;
const TcpHeader = proto.TcpHeader;
const Connection = @import("connection.zig");

const PacketReader = struct {
    reader: std.io.AnyReader,

    const Packet = struct {
        iph: ip.Header,
        tcph: TcpHeader,
        payload: []const u8,
    };

    pub fn readPacket(self: *PacketReader) !Packet {
        var buff: [std.mem.page_size]u8 = undefined;
        const n = try self.reader.read(&buff);
        const data = buff[0..n];

        const ip_packet = ip.Packet.parse(data);
        if (ip_packet.header.next_level_protocol != .Tcp) return error.InvalidProtocol;
        const tcp_header = TcpHeader.parse(ip_packet.data);

        return .{
            .iph = ip_packet.header,
            .tcph = tcp_header,
            .payload = ip_packet.data[tcp_header.dataOffset()..],
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

    // _ = try std.Thread.spawn(.{}, connect, .{});

    while (true) {
        const p = packet_reader.readPacket() catch continue;

        const conn: *Connection = blk: {
            // check if we have an open connection
            for (connections.items) |*con| if (con.addrs.local.getPort() == p.tcph.hdr.dest_port) break :blk con;
            // add new connection if it does not exist
            try connections.append(Connection.init(.{ .file = tun.dev }, .{
                .local = std.net.Ip4Address.init(p.iph.dest_ip, p.tcph.hdr.dest_port),
                .remote = std.net.Ip4Address.init(p.iph.source_ip, p.tcph.hdr.source_port),
            }));
            break :blk &connections.items[connections.items.len - 1];
        };

        try conn.handle_packet(p.iph, p.tcph, p.payload);
    }
}

pub fn connect() !void {
    // std.time.sleep(std.time.ns_per_s * 4);
    _ = try std.net.tcpConnectToAddress(
        try std.net.Address.resolveIp("192.168.0.2", 443),
    );
}

test {
    _ = @import("utils/checksum.zig");
}
