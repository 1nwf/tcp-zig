const std = @import("std");
const ip = @import("ip.zig");
const CheckSum = @import("../utils/checksum.zig");

pub const Header = extern struct {
    pub const Control = packed struct(u8) {
        /// No more data from sender
        fin: bool = false,
        /// Synchronize sequence numbers
        syn: bool = false,
        /// Reset the connection
        rst: bool = false,
        /// Push Function, dont buffer data and send later
        psh: bool = false,
        /// Acknowledgment field significant
        ack: bool = false,
        /// Urgent Pointer field significant
        urg: bool = false,
        /// ECN-Echo
        ece: bool = false,
        /// Congestion Window Reduced
        cwr: bool = false,
    };

    source_port: u16,
    dest_port: u16,

    /// When SYN flag is set, this is the initial sequence number
    /// otherwise, the sequence number of the first data octet in the segment
    seq_number: u32,

    /// When ACK flag is set, this field contains the value of the next sequence number the sender of the segment is expecting to receive
    /// Once a connection is established, this is always sent
    ack_number: u32,

    /// the number of 32-bit words in this header
    /// indicates where data begins
    data_offset: packed struct(u8) {
        _: u4 = 0, // reserved
        value: u4 = 5, // size of header in 32-bit words
    },

    ctrl: Control = .{},

    /// The number of data octets beginning with the one indicated in the
    /// acknowledgment field which the sender of this segment is willing to
    /// accept.
    window_size: u16,
    /// Checksum of the ip and tcp header as well as the data.
    checksum: u16 = 0,
    urgent_pointer: u16 = 0,

    comptime {
        std.debug.assert(@bitSizeOf(Header) / 8 == 20);
        std.debug.assert(@sizeOf(Header) == 20);
    }

    pub fn calcChecksum(
        self: *Header,
        source_ip: [4]u8,
        dest_ip: [4]u8,
        options: []const u8,
        payload: []const u8,
    ) void {
        var checksum = CheckSum{};
        self.checksum = 0;
        defer self.checksum = @byteSwap(checksum.final()); // update checksum

        var header = self.*;
        std.mem.byteSwapAllFields(Header, &header);
        const header_bytes = std.mem.asBytes(&header);

        // calc checksum for psuedo ip header
        checksum.addSlice(&source_ip);
        checksum.addSlice(&dest_ip);
        checksum.addSlice(&.{ 0, @intFromEnum(ip.IpNextHeaderProtocols.Tcp) });

        const len: u16 = @intCast(payload.len + options.len + header_bytes.len);
        checksum.addInt(u16, @byteSwap(len));

        // add header and payload data
        checksum.addSlice(header_bytes);

        if (options.len != 0) checksum.addSlice(options);
        if (payload.len != 0) checksum.addSlice(payload);
    }
};

hdr: Header,
options: []const u8 = &.{},
payload: []const u8 = &.{},

const Self = @This();

pub fn init(hdr: Header, options: []const u8, payload: []const u8) Self {
    return .{ .hdr = hdr, .options = options, .payload = payload };
}

pub fn parse(buff: []const u8) Self {
    var hdr = std.mem.bytesToValue(Header, buff);
    std.mem.byteSwapAllFields(Header, &hdr);

    var self = Self{ .hdr = hdr };

    if (hdr.data_offset.value > 5) {
        const start: usize = @sizeOf(Header);
        const end: usize = (@as(usize, @intCast(self.hdr.data_offset.value)) - 5) * 4;
        self.options = buff[start .. start + end];
    }

    self.payload = buff[self.dataOffset()..];
    return self;
}

pub fn dataOffset(self: Self) usize {
    const doff: usize = @intCast(self.hdr.data_offset.value);
    return doff * 4;
}

pub fn calcChecksum(self: *Self, source_ip: [4]u8, dest_ip: [4]u8) void {
    self.hdr.calcChecksum(source_ip, dest_ip, self.options, self.payload);
}

pub fn size(self: Self) usize {
    return @sizeOf(Header) + self.options.len + self.payload.len;
}

pub fn isAck(self: Self) bool {
    return std.meta.eql(self.hdr.ctrl, .{ .ack = true });
}

pub fn isCtrl(self: Self, ctrl: Header.Control) bool {
    return std.meta.eql(self.hdr.ctrl, ctrl);
}

pub fn endSequence(self: Self) u32 {
    return self.hdr.seq_number + @max(1, self.payload.len) - 1;
}
