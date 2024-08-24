const std = @import("std");
const Checksum = @import("../utils/checksum.zig");

pub const IpNextHeaderProtocols = enum(u8) {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    _,
};

pub const Header = extern struct {
    const Flags = packed struct(u3) {
        _: u1 = 0,
        dont_fragment: bool = true,
        more_fragments: bool = false,
    };

    // length of ip header in 32 bit increments
    version_and_header_length: packed struct(u8) {
        header_len: u4 = @bitSizeOf(Header) / 32,
        version: u4 = 4,
    } = .{},
    // version: u4 = 4, // always 4
    tos: u8 = 0, // this field is ignored
    // length of whole packet including payload
    total_length: u16 align(1),
    // identification number. used to identify related packets that are fragmented
    ident: u16 align(1),
    // flags and fragment offset of the payload from the original packet, measured as a multiple of 8 bytes.
    ffo: packed struct(u16) { offset: u13 = 0, flags: Flags = .{} } align(1),
    /// time to live. number of router hops allowed
    ttl: u8,
    next_level_protocol: IpNextHeaderProtocols,
    checksum: u16 align(1),
    source_ip: [4]u8,
    dest_ip: [4]u8,
    // options: ?[]u8 = null,  // optional

    pub fn parse(buff: []const u8) Header {
        var header = std.mem.bytesToValue(Header, buff[0..@sizeOf(Header)]);
        std.mem.byteSwapAllFields(Header, &header);

        return header;
    }

    pub fn init(
        source_ip: [4]u8,
        dest_ip: [4]u8,
        payload_type: IpNextHeaderProtocols,
        payload_len: usize,
    ) Header {
        var header = Header{
            .source_ip = source_ip,
            .dest_ip = dest_ip,
            .next_level_protocol = payload_type,
            .ttl = 64,
            .ident = 0,
            .checksum = 0,
            .total_length = @intCast(@sizeOf(Header) + payload_len),
            .ffo = .{},
        };

        var swapped = header;

        std.mem.byteSwapAllFields(Header, &swapped);
        header.checksum = @byteSwap(Checksum.fromSlice(std.mem.asBytes(&swapped)));
        return header;
    }

    comptime {
        std.debug.assert(@sizeOf(Header) == 20);
        std.debug.assert(@bitSizeOf(Header) == 160);
    }
};

pub const Packet = struct {
    header: Header,
    data: []const u8,

    pub fn init(
        source_ip: [4]u8,
        dest_ip: [4]u8,
        payload_type: IpNextHeaderProtocols,
        data: []const u8,
    ) Packet {
        var checksum = Checksum{};
        var header = Header{
            .source_ip = source_ip,
            .dest_ip = dest_ip,
            .next_level_protocol = payload_type,
            .ttl = 64,
            .ident = 0,
            .checksum = 0,
            .total_length = @intCast(@sizeOf(Header) + data.len),
            .ffo = .{},
        };
        checksum.addSlice(std.mem.asBytes(&header));
        header.checksum = checksum.final();

        return .{ .header = header, .data = data };
    }

    pub fn parse(buff: []const u8) Packet {
        return .{
            .header = Header.parse(buff[0..@sizeOf(Header)]),
            .data = buff[@sizeOf(Header)..],
        };
    }
};
