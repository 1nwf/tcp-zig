const std = @import("std");
const log = std.log.scoped(.netif);
const proto = @import("protocols/protocols.zig");
const ip = proto.ip;
const TcpSegment = proto.TcpSegment;
const TcpStream = @import("stream.zig");
const Connection = @import("connection.zig");
const StreamSource = @import("stream_source.zig").StreamSource;
const Ip4Address = Connection.Ip4Address;

const Packet = struct {
    iph: ip.Header,
    seg: TcpSegment,

    pub fn localAddr(self: Packet) Ip4Address {
        return .{
            .addr = self.iph.source_ip,
            .port = self.seg.hdr.source_port,
        };
    }

    pub fn remoteAddr(self: Packet) Ip4Address {
        return .{
            .addr = self.iph.dest_ip,
            .port = self.seg.hdr.dest_port,
        };
    }

    pub fn addrs(self: Packet) Connection.Address {
        return .{
            .local = self.remoteAddr(),
            .remote = self.localAddr(),
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

fn hasListener(self: *const Self, port: u16) bool {
    return self.listeners.get(port) != null;
}

fn processIncoming(self: *Self) !void {
    var reader = PacketReader{ .reader = self.stream.reader().any() };
    while (true) {
        switch (self.stream) {
            .file => |f| {
                // if the stream source is a file, use poll with the specified retransmission timeout to make sure that read does not block indefinitely
                // and retransmissions are sent on time
                var fds = [_]std.posix.pollfd{.{ .fd = f.handle, .events = std.posix.POLL.IN, .revents = 0 }};
                const ret = try std.posix.poll(&fds, @intCast(self.retransmit_timeout / std.time.ns_per_ms));
                std.debug.assert(ret == 0 or ret == 1);
            },
            else => {},
        }

        if (self.retransmitTimeoutElapsed()) {
            log.info("retransmit timeout elapsed", .{});
            var iter = self.connections.valueIterator();
            while (iter.next()) |conn| {
                try conn.retransmitUnackedSegments(self.retransmit_timeout);
            }
            // continue because if poll returned 0 (timed-out)
            // we don't want to block on the following read
            continue;
        }

        const packet = reader.readPacket() catch continue;

        if (!self.hasListener(packet.remoteAddr().port)) {
            log.warn("no listener exists for {}", .{packet.remoteAddr()});
            continue;
        }

        const res = try self.connections.getOrPut(packet.addrs());
        const conn = res.value_ptr;
        if (!res.found_existing) {
            conn.* = Connection.init(self.stream.writer().any(), packet.addrs(), self.allocator);
        }
        const syn_recv = conn.state == .syn_recvd;
        conn.handle_segment(packet.seg) catch |err| {
            log.err("tcp segment error: {}", .{err});
            continue;
        };

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
        } else if (conn.state == .closed or conn.state == .time_wait) {
            log.info("closing the connection", .{});
            // deinit and remove connection
            conn.deinit();
            std.debug.assert(self.connections.remove(conn.addrs));
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
