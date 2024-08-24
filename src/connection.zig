const std = @import("std");
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
    window: u32,
    urgent_pointer: u32,
    /// segment sequence number used for last window update
    last_window_update_seq: u32,
    /// segment acknowledgment number used for last window update
    last_window_update_ack: u32,
    /// initial sequence number
    initial_seq: u32,
};

const RecvSequence = struct {
    next: u32,
    window: u32,
    urgent_pointer: u32,
    initial_seq: u32,
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
) !void {
    switch (self.state) {
        .listen => {
            std.log.info("tccp header: {}", .{tcp_header.hdr});
            if (!tcp_header.hdr.ctrl.syn) @panic("packet is not syn");
            var syn_ack = TcpHeader.Header{
                .source_port = tcp_header.hdr.dest_port,
                .dest_port = tcp_header.hdr.source_port,
                .ctrl = .{ .syn = true, .ack = true },
                .seq_number = 300,
                .ack_number = tcp_header.hdr.seq_number + 1,
                .data_offset = .{},
                .window_size = tcp_header.hdr.window_size,
            };

            syn_ack.calcChecksum(ip_header.dest_ip, ip_header.source_ip, &.{}, &.{});
            // const ip_packet = ip.Packet.init(ip_header.dest_ip, ip_header.source_ip, .Tcp, std.mem.asBytes(&syn_ack));
            // ip.Header.init(ip_header.dest_ip, ip_header.source_ip, .Tcp, @sizeOf(TcpHeader.Header));

            const iph = ip.Header.init(ip_header.dest_ip, ip_header.source_ip, .Tcp, @sizeOf(TcpHeader.Header));
            std.log.info("iph: {}", .{iph});

            try self.stream.transmit(iph, TcpHeader{ .hdr = syn_ack }, &.{});

            // self.state = .syn_recvd;
            self.recv_seq.initial_seq = tcp_header.hdr.seq_number;
        },

        .syn_recvd => {
            if (!tcp_header.hdr.ctrl.ack) @panic("packet is not ack");
        },

        else => {},
    }
}
