const std = @import("std");
const log = std.log;
const ip = @import("protocols/ip.zig");
const TcpPacket = @import("protocols/tcp.zig");
const Self = @This();

pub const PacketStream = struct {
    stream: std.io.StreamSource,

    fn transmit(
        self: *PacketStream,
        ip_header: ip.Header,
        tcp_packet: TcpPacket,
    ) !void {
        var buff: [std.mem.page_size]u8 = undefined;
        var buff_writer = std.io.fixedBufferStream(&buff);

        try buff_writer.writer().writeStructEndian(ip_header, .big);
        try buff_writer.writer().writeStructEndian(tcp_packet.hdr, .big);

        if (tcp_packet.options.len != 0) @panic("todo");
        if (tcp_packet.payload.len != 0) try buff_writer.writer().writeAll(tcp_packet.payload);

        try self.stream.writer().writeAll(buff_writer.getWritten());
    }
};

const State = enum {
    closed,
    /// waiting for a connection request from any remote TCP peer and port.
    listen,
    /// waiting for a matching connection request after having sent a connection request.
    syn_sent,
    /// waiting for a confirming connection request acknowledgment after having both received and sent a connection request.
    syn_recvd,
    /// an open connection, data received can be delivered to the user. The normal state for the data transfer phase of the connection.
    established,
    /// waiting for a connection termination request from the remote TCP peer, or an acknowledgment of the connection termination request previously sent.
    fin_wait_1,
    /// waiting for a connection termination request from the remote TCP peer.
    fin_wait_2,
    /// waiting for a connection termination request from the local user.
    close_wait,
    /// waiting for a connection termination request acknowledgment from the remote TCP peer.
    closing,
    /// waiting for an acknowledgment of the connection termination request previously sent to the remote TCP peer
    last_ack,
    /// waiting for enough time to pass to be sure the remote TCP peer received the acknowledgment of its connection termination
    /// request and to avoid new connections being impacted by delayed segments from previous connections.
    time_wait,
};

const SendSequence = struct {
    /// send unacknowledged
    unacked: u32,
    /// send next
    next: u32,
    /// send window
    window: u16,
    urgent_pointer: u16,
    /// segment sequence number used for last window update
    last_window_update_seq: u32,
    /// segment acknowledgment number used for last window update
    last_window_update_ack: u32,
    /// initial sequence number
    initial_seq: u32,

    // A segment on the retransmission queue is fully acknowledged if the sum of its sequence number
    // and length is less than or equal to the acknowledgment value in the incoming segment.
    pub fn isValidAck(self: SendSequence, seg_ack: u32) bool {
        // TODO: need to handle wrapping sequence numbers
        return self.unacked < seg_ack and seg_ack <= self.next;
    }
};

const RecvSequence = struct {
    next: u32,
    window: u16,
    urgent_pointer: u16,
    initial_seq: u32,

    pub fn isValidRecv(self: RecvSequence, seq: u32, len: usize) bool {
        if (self.window == 0) return len == 0 and self.next == seq;
        if (len == 0) return (self.next <= seq and seq < self.next + self.window);
        return (self.next <= seq and seq < self.next + self.window) or
            (self.next <= seq + len and seq + len < self.next + self.window);
    }
};

pub const Ip4Address = struct { addr: [4]u8, port: u16 };
const ConnectionAddress = struct {
    local: Ip4Address,
    remote: Ip4Address,
};

addrs: ConnectionAddress,

state: State,
send_seq: SendSequence,
recv_seq: RecvSequence,
stream: PacketStream,

pub fn init(stream: std.io.StreamSource, addrs: ConnectionAddress) Self {
    return .{
        .state = .listen,
        .addrs = addrs,
        .send_seq = std.mem.zeroes(SendSequence),
        .recv_seq = std.mem.zeroes(RecvSequence),
        .stream = PacketStream{ .stream = stream },
    };
}

pub fn handle_packet(
    self: *Self,
    packet: TcpPacket,
) !void {
    if (self.state != .listen) {
        if (!self.send_seq.isValidAck(packet.hdr.ack_number)) return error.InvalidAck;
        if (!self.recv_seq.isValidRecv(packet.hdr.seq_number, packet.payload.len)) return error.InvalidRecvSeq;
    }
    switch (self.state) {
        .listen => {
            if (!packet.hdr.ctrl.syn) {
                log.info("packet is not syn", .{});
                return;
            }
            log.info("received syn: {}", .{packet.hdr.seq_number});
            defer log.info("sent syn-ack: {}", .{self.send_seq.initial_seq});
            self.recv_seq.window = packet.hdr.window_size; // TODO update this
            self.recv_seq.initial_seq = packet.hdr.seq_number;
            self.recv_seq.next = self.recv_seq.initial_seq + 1;

            self.send_seq.initial_seq = 300;
            self.send_seq.next = self.send_seq.initial_seq;
            try self.transmit(.{ .syn = true, .ack = true }, &.{});

            self.send_seq.window = packet.hdr.window_size;
            self.send_seq.unacked = self.send_seq.initial_seq;
            self.state = .syn_recvd;
        },
        // NOTE: simultaneous initiation and duplicate syn recovery is not currently supported
        .syn_recvd => {
            log.info("received ack: {}", .{packet.hdr.ack_number});
            if (!packet.hdr.ctrl.ack) {
                log.info("packet is not ack", .{});
                return;
            }

            if (!self.send_seq.isValidAck(packet.hdr.ack_number)) return error.InvalidAck;
            if (!self.recv_seq.isValidRecv(packet.hdr.seq_number, packet.payload.len)) return error.InvalidRecvSeq;
            self.state = .established;
        },
        .established => {
            std.debug.assert(packet.hdr.ack_number == self.send_seq.next);
            if (!self.recv_seq.isValidRecv(packet.hdr.seq_number, packet.payload.len)) return error.InvalidRecv;
            // received an ack packet. ignore for now
            if (packet.isAck()) return;
            // recieved connection termination request
            if (std.meta.eql(packet.hdr.ctrl, .{ .fin = true, .ack = true })) {}

            self.recv_seq.next = @intCast(packet.hdr.seq_number + @max(1, packet.payload.len));
            try self.transmit(.{ .ack = true }, &.{});
        },
        .fin_wait_1 => {
            std.debug.assert(packet.hdr.ctrl.ack);
            self.state = .fin_wait_2;
        },
        .fin_wait_2 => {
            std.debug.assert(packet.hdr.ctrl.ack);
            if (!std.meta.eql(packet.hdr.ctrl, .{ .ack = true, .fin = true })) return;

            self.recv_seq.next += @intCast(@max(1, packet.payload.len));
            try self.transmit(.{ .ack = true }, &.{});
            self.state = .time_wait;
        },

        else => {},
    }
}

pub fn send(self: *Self, data: []const u8) !void {
    if (self.state != .established) return error.ConnNotEstablished;
    try self.transmit(.{ .ack = true, .psh = true }, data);
}

fn transmit(self: *Self, ctl: TcpPacket.Header.Control, data: []const u8) !void {
    defer self.send_seq.next += @intCast(@max(1, data.len));
    var tcph = TcpPacket.init(.{
        .source_port = self.addrs.local.port,
        .dest_port = self.addrs.remote.port,
        .ctrl = ctl,
        .seq_number = self.send_seq.next,
        .ack_number = self.recv_seq.next,
        .data_offset = .{},
        .window_size = self.recv_seq.window,
    }, &.{}, data);
    tcph.calcChecksum(self.addrs.local.addr, self.addrs.remote.addr);

    const iph = ip.Header.init(self.addrs.local.addr, self.addrs.remote.addr, .Tcp, tcph.size());
    try self.stream.transmit(iph, tcph);
}

/// closing a connection blocks the user from sending more data, but still allows receiving data from the remote connection
pub fn close(self: *Self) !void {
    if (self.state != .established) return error.ConnNotEstablished;
    try self.transmit(.{ .ack = true, .fin = true }, &.{});
    self.state = .fin_wait_1;
}
