const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.tcp);
const ip = @import("protocols/ip.zig");
const TcpSegment = @import("protocols/tcp.zig");
const Self = @This();

pub const StreamSource = @import("stream_source.zig").StreamSource;

pub const DataBuffer = struct {
    const LinearFifo = std.fifo.LinearFifo(u8, .Dynamic);

    sem: std.Thread.Semaphore = .{},
    data: LinearFifo,
    fn init(allocator: std.mem.Allocator) DataBuffer {
        return .{ .data = LinearFifo.init(allocator) };
    }

    pub fn deinit(self: *DataBuffer) void {
        self.data.deinit();
    }

    pub fn read(self: *DataBuffer, buff: []u8) !usize {
        self.sem.wait();

        return self.data.read(buff);
    }

    pub fn write(self: *DataBuffer, data: []const u8) !void {
        try self.data.write(data);
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

    pub fn init(initial_seq: u32, window: u16) SendSequence {
        return .{
            .initial_seq = initial_seq,
            .unacked = initial_seq,
            .next = initial_seq,
            .window = window,
            .urgent_pointer = 0,
            .last_window_update_seq = 0,
            .last_window_update_ack = 0,
        };
    }

    pub fn ack(self: *SendSequence, ack_number: u32) !void {
        if (!self.isValidAck(ack_number)) return error.InvalidAck;
        self.unacked = ack_number;
    }

    pub fn sent(self: *SendSequence, len: usize) void {
        self.next += @intCast(@max(1, len));
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

    pub fn init(initial_seq: u32, window: u16) RecvSequence {
        return .{
            .next = initial_seq + 1,
            .window = window,
            .urgent_pointer = 0,
            .initial_seq = initial_seq,
        };
    }

    pub fn received(self: *RecvSequence, len: usize) void {
        self.next += @intCast(@max(1, len));
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
// an ordered list of unacked segments
// the sequence number of the first entry should == send_seq.unacked
unacked_segments: std.AutoArrayHashMap(u32, SegmentSent),
send_buffer: std.ArrayList(u8),
allocator: std.mem.Allocator,

pub fn flush(self: *Self) !void {
    if (self.send_buffer.items.len == 0) return;

    try self.transmit(
        .{ .psh = true, .ack = true },
        try self.send_buffer.toOwnedSlice(),
    );
}

pub fn init(writer: std.io.AnyWriter, addrs: Address, allocator: std.mem.Allocator) Self {
    return .{
        .state = .listen,
        .addrs = addrs,
        .send_seq = std.mem.zeroes(SendSequence),
        .recv_seq = std.mem.zeroes(RecvSequence),
        .writer = .{ .writer = writer },
        .data_buffer = DataBuffer.init(allocator),
        .unacked_segments = std.AutoArrayHashMap(u32, SegmentSent).init(allocator),
        .send_buffer = std.ArrayList(u8).init(allocator),
        .allocator = allocator,
    };
}

fn handleReset(self: *Self, segment: TcpSegment) !void {
    if (!segment.hdr.ctrl.rst) @panic("reset not set");

    if (segment.hdr.ctrl.ack) {
        if (!self.send_seq.isValidAck(segment.hdr.ack_number)) {
            return error.InvalidAck;
        }
    }

    if (self.state != .syn_sent and self.state != .listen) {
        if (!self.recv_seq.isValidRecv(segment.hdr.seq_number, segment.payload.len)) {
            return error.InvalidRecvSeq;
        }
    }

    switch (self.state) {
        .listen => return,
        .syn_recvd => {
            self.state = .listen;
        },
        else => self.state = .closed,
    }
}

pub fn handle_segment(self: *Self, segment: TcpSegment) !void {
    // received connection reset
    if (segment.hdr.ctrl.rst) {
        self.handleReset(segment) catch |e| log.warn("dropped rst packet: {}", .{e});
        return;
    }

    // validate segment seq and ack values
    if (segment.hdr.ctrl.ack) try self.handleSegmentAck(segment.hdr);
    if (!self.isValidSegmentSeq(segment)) return error.InvalidSemgent;

    switch (self.state) {
        .syn_sent => {
            std.debug.assert(segment.isCtrl(.{ .syn = true, .ack = true }));
            self.recv_seq = RecvSequence.init(segment.hdr.seq_number, segment.hdr.window_size);
            try self.transmit(.{ .ack = true }, &.{});
            self.state = .established;
        },
        .listen => {
            if (!segment.hdr.ctrl.syn) return;
            self.recv_seq = RecvSequence.init(segment.hdr.seq_number, segment.hdr.window_size);
            self.send_seq = SendSequence.init(300, self.recv_seq.window);

            try self.transmit(.{ .syn = true, .ack = true }, &.{});
            self.state = .syn_recvd;
        },
        // NOTE: simultaneous initiation and duplicate syn recovery is not currently supported
        .syn_recvd => {
            if (!segment.isAck()) return;
            self.state = .established;
        },
        .established => {
            // received an ack for an earlier sent segment
            if (segment.isAck()) return;
            // recieved connection termination request
            if (segment.hdr.ctrl.fin) {
                self.state = .close_wait;
            }
            if (segment.payload.len != 0) {
                try self.data_buffer.write(segment.payload);
            }
            self.recv_seq.received(segment.payload.len);
            try self.transmit(.{ .ack = true }, &.{});
        },
        .fin_wait_1 => {
            // handle simultaneous close sequence
            if (segment.isCtrl(.{ .fin = true, .ack = true })) {
                self.recv_seq.received(segment.payload.len);
                try self.transmit(.{ .ack = true }, &.{});
                self.state = .closing;
            } else if (segment.isAck()) {
                self.state = .fin_wait_2;
            } else @panic("invalid segment");
        },
        .fin_wait_2 => {
            std.debug.assert(segment.hdr.ctrl.ack);
            if (!segment.isCtrl(.{ .fin = true, .ack = true })) return;
            self.recv_seq.received(segment.payload.len);
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
    try self.send_buffer.appendSlice(data);
}

fn transmit(self: *Self, ctl: TcpSegment.Header.Control, data: []const u8) !void {
    const seg = self.constructSegment(ctl, data);
    const iph = ip.Header.init(self.addrs.local.addr, self.addrs.remote.addr, .Tcp, seg.size());
    try self.writer.transmit(iph, seg);

    // if this is not an ack packet, update the send_seq next value
    // and add it to the retransmit queue
    if (!seg.isAck()) {
        self.send_seq.sent(data.len);
        try self.unacked_segments.putNoClobber(
            @intCast(seg.hdr.seq_number + @max(data.len, 1)),
            SegmentSent.init(iph, seg, try std.time.Instant.now()),
        );
    }
}

pub fn handleSegmentAck(self: *Self, hdr: TcpSegment.Header) !void {
    std.debug.assert(hdr.ctrl.ack);
    if (self.unacked_segments.count() == 0) return;
    // return if the sequence ack is invalid
    self.send_seq.ack(hdr.ack_number) catch return;

    const segment_idx = self.unacked_segments.getIndex(hdr.ack_number) orelse return error.InvalidAck;
    for (0..segment_idx + 1) |_| {
        const key = self.unacked_segments.keys()[0];
        const entry = self.unacked_segments.fetchOrderedRemove(key) orelse unreachable;
        const segment = entry.value.seg;
        // free allocated data
        if (segment.payload.len != 0) {
            self.allocator.free(segment.payload);
        }
    }
}

/// validate segment sequence number
pub fn isValidSegmentSeq(self: Self, segment: TcpSegment) bool {
    return switch (self.state) {
        .listen, .syn_sent => true,
        else => self.recv_seq.isValidRecv(segment.hdr.seq_number, segment.payload.len),
    };
}

pub fn retransmitUnackedSegments(self: *Self, timeout_ns: u64) !void {
    for (self.unacked_segments.values()) |*value| {
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
    switch (self.state) {
        .listen => self.state = .closed,
        .established, .close_wait => |state| {
            try self.transmit(.{ .fin = true, .ack = true }, &.{});
            self.state = switch (state) {
                .close_wait => .last_ack,
                .established => .fin_wait_1,
                else => unreachable,
            };
        },
        .syn_sent => self.state = .closed,
        .syn_recvd => self.state = .closed,
        .fin_wait_1, .fin_wait_2, .closing, .last_ack, .time_wait => return,
        .closed => {},
    }
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
    self.send_buffer.deinit();
}

// ----------------- utilities for testing -----------------

// currently only used for testing
// needs update
fn connect(self: *Self) !void {
    self.send_seq.initial_seq = 300;
    self.send_seq.unacked = 300;
    self.send_seq.next = 300;
    self.recv_seq.window = 6400;

    try self.transmit(.{ .syn = true }, &.{});
    self.state = .syn_sent;
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
        for (self.buff.items) |d| self.allocator.free(d);
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

const expectEqual = std.testing.expectEqual;

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

test "send ack" {
    var s1 = TestBuffStream.init();
    var s2 = TestBuffStream.init();
    defer s1.deinit();
    defer s2.deinit();

    var t1 = TestConn.init(std.mem.zeroes(Address), s1.writer(), s2.reader());
    var t2 = TestConn.init(std.mem.zeroes(Address), s2.writer(), s1.reader());
    defer t1.conn.deinit();
    defer t2.conn.deinit();

    try t1.finishHandshake(&t2);

    const data_to_send = "test...the network";
    try t1.conn.send(data_to_send);
    try t1.conn.flush();

    try t2.process();
    try expectEqual(319, t2.conn.recv_seq.next);
    try expectEqual(data_to_send.len, t2.conn.data_buffer.data.count);

    var buff: [32]u8 = undefined;
    const n = try t2.conn.data_buffer.read(&buff);
    try expectEqual(data_to_send.len, n);
    try std.testing.expectEqualSlices(u8, data_to_send, buff[0..n]);

    try expectEqual(301, t1.conn.send_seq.unacked);
    try t1.process();
    try expectEqual(t1.conn.send_seq.next, t1.conn.send_seq.unacked);
    try expectEqual(319, t1.conn.send_seq.next);
    try expectEqual(0, t1.conn.unacked_segments.count());
    try expectEqual(0, t1.conn.send_buffer.items.len);
}

test "ack multiple segments" {
    var s1 = TestBuffStream.init();
    var s2 = TestBuffStream.init();
    defer s1.deinit();
    defer s2.deinit();

    var t1 = TestConn.init(std.mem.zeroes(Address), s1.writer(), s2.reader());
    var t2 = TestConn.init(std.mem.zeroes(Address), s2.writer(), s1.reader());
    defer t1.conn.deinit();
    defer t2.conn.deinit();

    try t1.finishHandshake(&t2);

    // send segments
    try t1.conn.send("test...");
    try t1.conn.flush();

    try t1.conn.send("the network");
    try t1.conn.flush();

    // handle ack both segments
    try t1.conn.handle_segment(.{
        .hdr = .{
            .source_port = 0,
            .dest_port = 0,
            .seq_number = t2.conn.send_seq.next,
            .ack_number = t2.conn.recv_seq.next + 18,
            .ctrl = .{ .ack = true },
            .window_size = 6400,
            .data_offset = .{},
        },
    });

    try expectEqual(0, t1.conn.unacked_segments.count());
}
