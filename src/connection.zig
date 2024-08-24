const std = @import("std");
const log = std.log;
const ip = @import("protocols/ip.zig");
const TcpHeader = @import("protocols/tcp.zig");
const Self = @This();

pub const PacketStream = struct {
    stream: std.io.StreamSource,

    fn transmit(
        self: *PacketStream,
        ip_header: ip.Header,
        tcp_header: TcpHeader,
        payload: []const u8,
    ) !void {
        var buff: [1024]u8 = undefined;
        var buff_writer = std.io.fixedBufferStream(&buff);

        try buff_writer.writer().writeStructEndian(ip_header, .big);
        try buff_writer.writer().writeStructEndian(tcp_header.hdr, .big);

        if (tcp_header.options.len != 0) @panic("todo");
        if (payload.len != 0) @panic("todo");

        try self.stream.writer().writeAll(buff_writer.getWritten());
    }
};

const State = enum {
    closed,
    listen,
    syn_sent,
    syn_recvd,
    established,
    fin_wait_1,
    fin_wait_2,
    close_wait,
    last_ack,
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

    pub fn isValidRecv(self: *RecvSequence, seq: u32, len: usize) bool {
        if (self.window == 0) return len == 0 and self.next == seq;
        if (len == 0) return (self.next <= seq and seq < self.next + self.window);
        return (self.next <= seq and seq < self.next + self.window) or
            (self.next <= seq + len and seq + len < self.next + self.window);
    }
};

const ConnectionAddress = struct {
    local: std.net.Ip4Address,
    remote: std.net.Ip4Address,
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
    ip_header: ip.Header,
    tcp_header: TcpHeader,
    payload: []const u8,
) !void {
    _ = payload;
    switch (self.state) {
        .listen => {
            if (!tcp_header.hdr.ctrl.syn) @panic("packet is not syn");
            log.info("received syn", .{});
            defer log.info("sent syn-ack", .{});
            self.recv_seq.window = tcp_header.hdr.window_size; // TODO update this
            self.recv_seq.initial_seq = tcp_header.hdr.seq_number;
            self.recv_seq.next = self.recv_seq.initial_seq + 1;

            var syn_ack = TcpHeader.Header{
                .source_port = tcp_header.hdr.dest_port,
                .dest_port = tcp_header.hdr.source_port,
                .ctrl = .{ .syn = true, .ack = true },
                .seq_number = 300,
                .ack_number = tcp_header.hdr.seq_number + 1,
                .data_offset = .{},
                .window_size = self.recv_seq.window,
            };
            syn_ack.calcChecksum(ip_header.dest_ip, ip_header.source_ip, &.{}, &.{});
            const iph = ip.Header.init(ip_header.dest_ip, ip_header.source_ip, .Tcp, @sizeOf(TcpHeader.Header));
            try self.stream.transmit(iph, TcpHeader{ .hdr = syn_ack }, &.{});

            self.send_seq.next = syn_ack.seq_number + 1;
            self.send_seq.window = tcp_header.hdr.window_size;
            self.send_seq.initial_seq = syn_ack.seq_number;
            self.send_seq.unacked = syn_ack.seq_number;
            self.state = .syn_recvd;
        },
        // NOTE: simultaneous initiation and duplicate syn recovery is not currently supported
        .syn_recvd => {
            log.info("received ack", .{});
            if (!tcp_header.hdr.ctrl.ack) @panic("packet is not ack");
            if (!self.send_seq.isValidAck(tcp_header.hdr.ack_number)) return error.InvaliAck;
            self.state = .established;
        },
        .established => {
            log.info("got packet in established state", .{});
        },
        else => {},
    }
}
