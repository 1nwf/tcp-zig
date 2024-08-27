const std = @import("std");
const assert = std.debug.assert;
const log = std.log;
const ip = @import("protocols/ip.zig");
const TcpSegment = @import("protocols/tcp.zig");
const Self = @This();

pub const DataBuffer = struct {
    sem: std.Thread.Semaphore = .{},
    data: std.ArrayList([]const u8),
    fn init(allocator: std.mem.Allocator) DataBuffer {
        return .{ .data = std.ArrayList([]const u8).init(allocator) };
    }
    pub fn deinit(self: *DataBuffer) void {
        self.data.deinit();
    }

    pub fn read(self: *DataBuffer) ![]const u8 {
        self.sem.wait();
        return self.data.pop();
    }

    pub fn write(self: *DataBuffer, data: []const u8) !void {
        try self.data.append(data);
        self.sem.post();
    }
};

pub const PacketWriter = struct {
    writer: std.io.AnyWriter,

    fn transmit(
        self: *PacketWriter,
        ip_header: ip.Header,
        segment: TcpSegment,
    ) !void {
        var buff: [std.mem.page_size]u8 = undefined;
        var buff_writer = std.io.fixedBufferStream(&buff);

        try buff_writer.writer().writeStructEndian(ip_header, .big);
        try buff_writer.writer().writeStructEndian(segment.hdr, .big);

        if (segment.options.len != 0) @panic("todo");
        if (segment.payload.len != 0) try buff_writer.writer().writeAll(segment.payload);

        try self.writer.writeAll(buff_writer.getWritten());
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
pub const Address = struct {
    local: Ip4Address,
    remote: Ip4Address,
};

const SegmentSent = struct {
    iph: ip.Header,
    seg: TcpSegment,
    /// instant of when the segment was sent
    t: std.time.Instant,

    fn init(iph: ip.Header, seg: TcpSegment, t: std.time.Instant) SegmentSent {
        return .{ .iph = iph, .seg = seg, .t = t };
    }

    fn shouldRetransmit(self: SegmentSent, timeout_ns: u64) bool {
        const now = std.time.Instant.now() catch @panic("unable to get time");
        return now.since(self.t) >= timeout_ns;
    }
};

addrs: Address,

state: State,
send_seq: SendSequence,
recv_seq: RecvSequence,
writer: PacketWriter,
// buffer used to store data that was received by this connection
data_buffer: DataBuffer,
// a hash map of seq+len and tcp segment
// TODO: store all bytes sent in one buffer
unacked_segments: std.AutoHashMap(u32, SegmentSent),

pub fn init(writer: std.io.AnyWriter, addrs: Address, allocator: std.mem.Allocator) Self {
    return .{
        .state = .listen,
        .addrs = addrs,
        .send_seq = std.mem.zeroes(SendSequence),
        .recv_seq = std.mem.zeroes(RecvSequence),
        .writer = .{ .writer = writer },
        .data_buffer = DataBuffer.init(allocator),
        .unacked_segments = std.AutoHashMap(u32, SegmentSent).init(allocator),
    };
}

// TODO: handle reset
pub fn handle_segment(
    self: *Self,
    segment: TcpSegment,
) !void {
    if (self.state != .listen and self.state != .syn_sent) {
        if (!self.send_seq.isValidAck(segment.hdr.ack_number)) return error.InvalidAck;
        if (!self.recv_seq.isValidRecv(segment.hdr.seq_number, segment.payload.len)) return error.InvalidRecvSeq;
    }

    // remove from retransmit queue and update send.unacked
    if (segment.isAck()) self.handleSegmentAck(segment.hdr.ack_number);
    switch (self.state) {
        .syn_sent => {
            std.debug.assert(std.meta.eql(segment.hdr.ctrl, .{ .syn = true, .ack = true }));

            self.recv_seq.window = segment.hdr.window_size; // TODO update this
            self.recv_seq.initial_seq = segment.hdr.seq_number;
            self.recv_seq.next = self.recv_seq.initial_seq + 1;
            self.send_seq.window = segment.hdr.window_size;

            try self.transmit(.{ .ack = true }, &.{});
            self.state = .established;
        },
        .listen => {
            if (!segment.hdr.ctrl.syn) {
                log.info("packet is not syn", .{});
                return;
            }
            log.info("received syn: {}", .{segment.hdr.seq_number});
            defer log.info("sent syn-ack: {}", .{self.send_seq.initial_seq});
            self.recv_seq.window = segment.hdr.window_size; // TODO update this
            self.recv_seq.initial_seq = segment.hdr.seq_number;
            self.recv_seq.next = self.recv_seq.initial_seq + 1;

            self.send_seq.initial_seq = 300;
            self.send_seq.next = self.send_seq.initial_seq;
            try self.transmit(.{ .syn = true, .ack = true }, &.{});

            self.send_seq.window = segment.hdr.window_size;
            self.send_seq.unacked = self.send_seq.initial_seq;
            self.state = .syn_recvd;
        },
        // NOTE: simultaneous initiation and duplicate syn recovery is not currently supported
        .syn_recvd => {
            log.info("received ack: {}", .{segment.hdr.ack_number});
            if (!segment.isAck()) {
                log.info("packet is not ack", .{});
                return;
            }

            self.state = .established;
        },
        .established => {
            // received an ack for an earlier sent segment
            if (segment.isAck()) return;

            // recieved connection termination request
            if (std.meta.eql(segment.hdr.ctrl, .{ .fin = true, .ack = true })) {
                self.state = .close_wait;
            }

            if (segment.payload.len != 0) {
                try self.data_buffer.write(segment.payload);
            }

            self.recv_seq.next += @intCast(@max(1, segment.payload.len));
            try self.transmit(.{ .ack = true }, &.{});
        },
        .fin_wait_1 => {
            // handle simultaneous close sequence
            if (std.meta.eql(segment.hdr.ctrl, .{ .fin = true, .ack = true })) {
                self.recv_seq.next += @intCast(@max(1, segment.payload.len));
                try self.transmit(.{ .ack = true }, &.{});
                self.state = .closing;
            } else if (segment.isAck()) {
                self.state = .fin_wait_2;
            } else @panic("invalid segment");
        },
        .fin_wait_2 => {
            std.debug.assert(segment.hdr.ctrl.ack);
            if (!std.meta.eql(segment.hdr.ctrl, .{ .ack = true, .fin = true })) return;

            self.recv_seq.next += @intCast(@max(1, segment.payload.len));
            try self.transmit(.{ .ack = true }, &.{});
            self.state = .time_wait;
        },
        .close_wait => {
            if (segment.payload.len != 0) {
                try self.data_buffer.write(segment.payload);
            }
        },
        .closing => {
            std.debug.assert(segment.isAck());
            self.state = .time_wait;
        },
        .last_ack => {
            std.debug.assert(segment.isAck());
            self.state = .closed;
        },
        .time_wait => {
            // must wait for 2xMSL(max segment lifetime)
            // before closing a connection
        },
        else => {},
    }
}

pub fn send(self: *Self, data: []const u8) !void {
    if (self.state != .established) return error.ConnNotEstablished;
    try self.transmit(.{ .ack = true, .psh = true }, data);
}

fn transmit(self: *Self, ctl: TcpSegment.Header.Control, data: []const u8) !void {
    const seg = self.constructSegment(ctl, data);
    const iph = ip.Header.init(self.addrs.local.addr, self.addrs.remote.addr, .Tcp, seg.size());
    try self.writer.transmit(iph, seg);

    if (!seg.isAck()) {
        // if this is not an ack packet, update the seq next value
        self.send_seq.next += @intCast(@max(1, data.len));
        try self.unacked_segments.putNoClobber(
            @intCast(seg.hdr.seq_number + @max(1, data.len)),
            SegmentSent.init(iph, seg, try std.time.Instant.now()),
        );
    }
}

pub fn handleSegmentAck(self: *Self, seq: u32) void {
    const value = self.unacked_segments.getPtr(seq) orelse @panic("acked segment does not exist");
    // update send unacked value
    self.send_seq.unacked += @intCast(value.seg.payload.len);
    // remove value from unacked_segments
    _ = self.unacked_segments.remove(seq);
}

pub fn retransmitUnackedSegments(self: *Self, timeout_ns: u64) !void {
    var iter = self.unacked_segments.valueIterator();
    while (iter.next()) |value| {
        if (value.shouldRetransmit(timeout_ns)) {
            try self.writer.transmit(value.iph, value.seg);
            // update send time
            value.t = try std.time.Instant.now();
        }
    }
}

/// closing a connection blocks the user from sending more data, but still allows receiving data from the remote connection
pub fn close(self: *Self) !void {
    if (self.state != .established and self.state != .close_wait) return error.ConnNotEstablished;
    try self.transmit(.{ .ack = true, .fin = true }, &.{});

    self.state = switch (self.state) {
        .close_wait => .last_ack,
        .established => .fin_wait_1,
        else => unreachable,
    };
}

fn constructSegment(self: *Self, ctl: TcpSegment.Header.Control, data: []const u8) TcpSegment {
    var seg = TcpSegment.init(.{
        .source_port = self.addrs.local.port,
        .dest_port = self.addrs.remote.port,
        .ctrl = ctl,
        .seq_number = self.send_seq.next,
        .ack_number = self.recv_seq.next,
        .data_offset = .{},
        .window_size = self.recv_seq.window,
    }, &.{}, data);
    seg.calcChecksum(self.addrs.local.addr, self.addrs.remote.addr);
    return seg;
}

pub fn deinit(self: *Self) void {
    self.unacked_segments.deinit();
    self.data_buffer.deinit();
}

// currently only used for testing
// needs update
fn connect(self: *Self) !void {
    self.send_seq.initial_seq = 300;
    self.send_seq.unacked = 300;
    self.send_seq.next = 301;

    try self.transmit(.{ .syn = true }, &.{});
    self.state = .syn_sent;
}

test "3-way handshake" {
    var s1 = TestBuffStream.init();
    var s2 = TestBuffStream.init();
    defer s1.deinit();
    defer s2.deinit();

    var t1 = TestConn.init(std.mem.zeroes(Address), s1.writer(), s2.reader());
    var t2 = TestConn.init(std.mem.zeroes(Address), s2.writer(), s1.reader());
    defer t1.conn.deinit();
    defer t2.conn.deinit();

    // sent syn segment
    try t1.conn.connect();
    try std.testing.expectEqual(t1.conn.state, State.syn_sent);
    try std.testing.expectEqual(t2.conn.state, State.listen);

    // process syn segment and send syn-ack
    try t2.process();
    try std.testing.expectEqual(t2.conn.state, State.syn_recvd);

    // process syn-ack and send ack
    try t1.process();
    try std.testing.expectEqual(t1.conn.state, State.established);

    // process ack and update state
    try t2.process();
    try std.testing.expectEqual(t2.conn.state, State.established);

    // check that no data was written from previous call
    try std.testing.expectEqual(s1.buff.items.len, 0);
    try std.testing.expectEqual(s2.buff.items.len, 0);
}

test "close" {
    var s1 = TestBuffStream.init();
    var s2 = TestBuffStream.init();
    defer s1.deinit();
    defer s2.deinit();

    var t1 = TestConn.init(std.mem.zeroes(Address), s1.writer(), s2.reader());
    var t2 = TestConn.init(std.mem.zeroes(Address), s2.writer(), s1.reader());
    defer t1.conn.deinit();
    defer t2.conn.deinit();

    try t1.finishHandshake(&t2);

    try t1.conn.close();
    try std.testing.expectEqual(t1.conn.state, State.fin_wait_1);

    try t2.process();
    try std.testing.expectEqual(t2.conn.state, State.close_wait);

    try t1.process();
    try std.testing.expectEqual(t1.conn.state, State.fin_wait_2);

    try t2.conn.close();
    try std.testing.expectEqual(t2.conn.state, State.last_ack);

    try t1.process();
    try std.testing.expectEqual(t1.conn.state, State.time_wait);

    // NOTE: state should be updated?
    try t2.process();
    try std.testing.expectEqual(t2.conn.state, State.closed);
}

test "simultaneous close" {
    var s1 = TestBuffStream.init();
    var s2 = TestBuffStream.init();
    defer s1.deinit();
    defer s2.deinit();

    var t1 = TestConn.init(std.mem.zeroes(Address), s1.writer(), s2.reader());
    var t2 = TestConn.init(std.mem.zeroes(Address), s2.writer(), s1.reader());
    defer t1.conn.deinit();
    defer t2.conn.deinit();

    try t1.finishHandshake(&t2);

    try t1.conn.close();
    try t2.conn.close();
    try std.testing.expectEqual(t1.conn.state, State.fin_wait_1);
    try std.testing.expectEqual(t2.conn.state, State.fin_wait_1);

    try t2.process();
    try t1.process();
    try std.testing.expectEqual(t2.conn.state, State.closing);
    try std.testing.expectEqual(t1.conn.state, State.closing);

    try t2.process();
    try t1.process();
    try std.testing.expectEqual(t2.conn.state, State.time_wait);
    try std.testing.expectEqual(t1.conn.state, State.time_wait);
}

const TestBuffStream = struct {
    buff: std.ArrayList([]u8),
    allocator: std.mem.Allocator,
    pub fn init() TestBuffStream {
        return .{
            .buff = std.ArrayList([]u8).init(std.testing.allocator),
            .allocator = std.testing.allocator,
        };
    }

    pub fn reader(self: *const TestBuffStream) std.io.AnyReader {
        return .{ .context = @ptrCast(self), .readFn = @ptrCast(&read) };
    }

    pub fn writer(self: *const TestBuffStream) std.io.AnyWriter {
        return .{ .context = @ptrCast(self), .writeFn = @ptrCast(&write) };
    }

    fn read(self: *TestBuffStream, buffer: []u8) anyerror!usize {
        if (self.buff.items.len == 0) return error.NoData;
        const data = self.buff.orderedRemove(0);
        defer self.allocator.free(data);

        if (buffer.len < data.len) return error.BuffTooSmall;
        @memcpy(buffer[0..data.len], data);
        return data.len;
    }

    fn write(self: *TestBuffStream, bytes: []const u8) anyerror!usize {
        const slice = try self.allocator.alloc(u8, bytes.len);
        @memcpy(slice, bytes);
        try self.buff.append(slice);
        return bytes.len;
    }

    fn deinit(self: *TestBuffStream) void {
        // for (self.buff.items) |d| self.allocator.free(d);
        self.buff.deinit();
    }
};

const TestConn = struct {
    conn: Self,
    reader: std.io.AnyReader,

    pub fn init(addrs: Address, writer: std.io.AnyWriter, reader: std.io.AnyReader) TestConn {
        return .{ .conn = Self.init(writer, addrs, std.testing.allocator), .reader = reader };
    }

    pub fn process(self: *TestConn) !void {
        var buff: [std.mem.page_size]u8 = std.mem.zeroes([std.mem.page_size]u8);
        const n = try self.reader.read(&buff);
        const data = buff[0..n];

        const iph = ip.Packet.parse(data);
        const seg = TcpSegment.parse(iph.data);

        try self.conn.handle_segment(seg);
    }

    pub fn finishHandshake(self: *TestConn, other: *TestConn) !void {
        // sent syn segment
        try self.conn.connect();
        try std.testing.expectEqual(self.conn.state, State.syn_sent);
        try std.testing.expectEqual(other.conn.state, State.listen);
        // process syn segment and send syn-ack
        try other.process();
        try std.testing.expectEqual(other.conn.state, State.syn_recvd);
        // process syn-ack and send ack
        try self.process();
        try std.testing.expectEqual(self.conn.state, State.established);
        // process ack and update state
        try other.process();
        try std.testing.expectEqual(other.conn.state, State.established);
    }
};
