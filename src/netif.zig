const std = @import("std");
const log = std.log;
const proto = @import("protocols/protocols.zig");
const ip = proto.ip;
const TcpSegment = proto.TcpSegment;
const TcpStream = @import("stream.zig");
const Connection = @import("connection.zig");
pub const StreamSource = @import("stream_source.zig").StreamSource;

const Packet = struct {
    iph: ip.Header,
    seg: TcpSegment,

    pub fn addrs(self: Packet) Connection.Address {
        return .{
            .local = .{
                .addr = self.iph.dest_ip,
                .port = self.seg.hdr.dest_port,
            },
            .remote = .{
                .addr = self.iph.source_ip,
                .port = self.seg.hdr.source_port,
            },
        };
    }
};

const PacketReader = struct {
    reader: std.io.AnyReader,

    buff: [std.mem.page_size]u8 = undefined,
    pub fn readPacket(self: *PacketReader) !Packet {
        const n = try self.reader.read(&self.buff);
        const data = self.buff[0..n];

        const ip_packet = ip.Packet.parse(data);
        if (ip_packet.header.next_level_protocol != .Tcp) return error.InvalidProtocol;
        const segment = TcpSegment.parse(ip_packet.data);

        return .{
            .iph = ip_packet.header,
            .seg = segment,
        };
    }
};

const Self = @This();
const ActiveConnections = std.AutoHashMap(Connection.Address, Connection);

stream: std.io.StreamSource,
connections: ActiveConnections,
listeners: std.AutoHashMap(u16, TcpListener),

timer: std.time.Timer,
allocator: std.mem.Allocator,
retransmit_timeout: u64 = 1 * std.time.ns_per_s,

pub fn init(stream: std.io.StreamSource, allocator: std.mem.Allocator) !Self {
    return .{
        .stream = stream,
        .connections = ActiveConnections.init(allocator),
        .listeners = std.AutoHashMap(u16, TcpListener).init(allocator),
        .allocator = allocator,
        .timer = try std.time.Timer.start(),
    };
}

/// start processing incoming packets in a separate thread
pub fn start(self: *Self) !std.Thread {
    return std.Thread.spawn(.{}, processIncoming, .{self});
}

pub fn retransmitTimeoutElapsed(self: *Self) bool {
    return self.timer.lap() >= self.retransmit_timeout;
}

fn processIncoming(self: *Self) !void {
    var reader = PacketReader{ .reader = self.stream.reader().any() };
    while (true) {
        if (self.retransmitTimeoutElapsed()) {
            log.info("retransmit timeout elapsed", .{});
            var iter = self.connections.valueIterator();
            while (iter.next()) |conn| {
                try conn.retransmitUnackedSegments(self.retransmit_timeout);
            }
        }

        const packet = reader.readPacket() catch continue;
        const res = try self.connections.getOrPut(packet.addrs());
        const conn = res.value_ptr;
        if (!res.found_existing) {
            conn.* = Connection.init(self.stream.writer().any(), packet.addrs(), self.allocator);
        }
        const syn_recv = conn.state == .syn_recvd;
        try conn.handle_segment(packet.seg);
        if (syn_recv and conn.state == .established) {
            const dest_port = packet.seg.hdr.dest_port;
            // connection established, notify listener
            const lis = self.listeners.getPtr(dest_port) orelse continue;
            if (lis.stream.closed) {
                log.info("stream is closed, deiniting and removing....: {}", .{dest_port});
                // free listener if user closed the stream.
                lis.stream.deinit();
                std.debug.assert(self.listeners.remove(dest_port));
            } else {
                try lis.stream.write(conn);
            }
        }
    }
}

const TcpListener = struct {
    stream: StreamSource(*Connection),

    pub fn accept(self: *TcpListener) !?TcpStream {
        const conn = try self.stream.read() orelse return null;
        return TcpStream.init(conn);
    }

    pub fn deinit(self: *TcpListener) void {
        self.stream.close();
    }
};

/// create a tcp Listener and bind it to a port
pub fn initListener(self: *Self, port: u16) !*TcpListener {
    const res = try self.listeners.getOrPut(port);
    if (!res.found_existing) {
        res.value_ptr.* = TcpListener{
            .stream = StreamSource(*Connection).init(self.allocator),
        };
    }
    return res.value_ptr;
}
