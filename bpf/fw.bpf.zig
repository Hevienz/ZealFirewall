const std = @import("std");

const bpf = @import("bpf");
const Xdp = bpf.Xdp;
const BPF = std.os.linux.BPF;
const helpers = BPF.kern.helpers;
const trace_printk = std.os.linux.BPF.kern.helpers.trace_printk;

const __u8 = u8;
const __be16 = u16;
const __be32 = u32;
const __sum16 = u16;
const __u16 = u16;

const EthHdr = extern struct {
    dest: [6]u8,
    src: [6]u8,
    proto: u16,
};

const IPv4Hdr = extern struct {
    ver_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    proto: u8,
    check: u16,
    src: u32,
    dst: u32,
};

const IPv6Hdr = extern struct {
    flow: u32,
    plen: u16,
    nxt: u8,
    hlim: u8,
    src: [16]u8,
    dst: [16]u8,
};

const TcpHdr = packed struct {
    source: __be16,
    dest: __be16,
    seq: __be32,
    ack_seq: __be32,
    res1: u4,
    doff: u4,
    fin: u1,
    syn: u1,
    rst: u1,
    psh: u1,
    ack: u1,
    urg: u1,
    ece: u1,
    cwr: u1,
    window: __be16,
    check: __sum16,
    urg_ptr: __be16,
};

const UdpHdr = extern struct {
    source: __be16,
    dest: __be16,
    len: __be16,
    check: __sum16,
};

const In6Addr = extern struct {
    in6_u: extern union {
        u6_addr8: [16]__u8,
        u6_addr16: [8]__be16,
        u6_addr32: [4]__be32,
    },
};

const AclKey = struct {
    ip_src_addr: In6Addr,
    dst_port: u16,
    ip_proto: u8,
    reserved: u8,
};

var acl_map = bpf.Map.HashMap("acl_map", AclKey, u64, 64, 0).init();

export fn firewall(ctx: *Xdp.Meta) linksection("xdp") c_int {
    const eth_hdr: *const EthHdr = ctx.get_ptr(EthHdr, 0) orelse return @intFromEnum(Xdp.RET.drop);

    const proto_ip4 = 0x0800;
    const proto_ip6 = 0x86DD;

    const ret = switch (eth_hdr.proto) {
        std.mem.nativeTo(u16, proto_ip4, .big) => handle_ipv4(ctx),
        std.mem.nativeTo(u16, proto_ip6, .big) => handle_ipv6(ctx),
        else => {
            return @intFromEnum(Xdp.RET.aborted);
        },
    };
    return ret;
}

fn handle_ipv4(ctx: *Xdp.Meta) c_int {
    const iphdr_offset = @sizeOf(EthHdr);
    const ipv4hdr: *const IPv4Hdr = ctx.get_ptr(IPv4Hdr, iphdr_offset) orelse return @intFromEnum(Xdp.RET.aborted);

    const IPPROTO_ICMP = 1;
    const IPPROTO_TCP = 6;
    const IPPROTO_UDP = 17;
    if (ipv4hdr.proto == IPPROTO_ICMP) {
        return @intFromEnum(Xdp.RET.pass);
    } else if (ipv4hdr.proto == IPPROTO_TCP) {
        const tcpHdr: *const TcpHdr = ctx.get_ptr(TcpHdr, iphdr_offset + (ipv4hdr.ver_ihl * 4)) orelse return @intFromEnum(Xdp.RET.aborted);

        if (!(tcpHdr.syn == 1 and tcpHdr.ack == 0)) {
            return @intFromEnum(Xdp.RET.pass);
        }

        const ipv4addr = u32_to_bytes(ipv4hdr.src);

        const ipv6addr = In6Addr{
            .in6_u = .{
                .u6_addr8 = [16]__u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, ipv4addr[0], ipv4addr[1], ipv4addr[2], ipv4addr[3] },
            },
        };

        const acl_key = AclKey{
            .ip_src_addr = ipv6addr,
            .ip_proto = ipv4hdr.proto,
            .dst_port = tcpHdr.dest,
            .reserved = 0,
        };

        const acl_val = acl_map.lookup(acl_key);
        if (acl_val) |val| {
            val.* += 1;
            return @intFromEnum(Xdp.RET.pass);
        } else {
            return @intFromEnum(Xdp.RET.drop);
        }
    } else if (ipv4hdr.proto == IPPROTO_UDP) {
        const udpHdr: *const UdpHdr = ctx.get_ptr(UdpHdr, iphdr_offset + (ipv4hdr.ver_ihl * 4)) orelse return @intFromEnum(Xdp.RET.aborted);
        const ipv4addr = u32_to_bytes(ipv4hdr.src);
        const ipv6addr = In6Addr{
            .in6_u = .{
                .u6_addr8 = [16]__u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, ipv4addr[0], ipv4addr[1], ipv4addr[2], ipv4addr[3] },
            },
        };

        const acl_key = AclKey{
            .ip_src_addr = ipv6addr,
            .ip_proto = ipv4hdr.proto,
            .dst_port = udpHdr.dest,
            .reserved = 0,
        };

        const acl_val = acl_map.lookup(acl_key);
        if (acl_val) |val| {
            val.* += 1;
            return @intFromEnum(Xdp.RET.pass);
        } else {
            return @intFromEnum(Xdp.RET.drop);
        }
    } else {
        return @intFromEnum(Xdp.RET.drop);
    }
}

fn handle_ipv6(ctx: *Xdp.Meta) c_int {
    const iphdr_offset = @sizeOf(EthHdr);
    const ipv6hdr: *const IPv6Hdr = ctx.get_ptr(IPv6Hdr, iphdr_offset) orelse return @intFromEnum(Xdp.RET.aborted);

    const IPPROTO_ICMPV6 = 58;
    const IPPROTO_TCP = 6;
    const IPPROTO_UDP = 17;
    if (ipv6hdr.nxt == IPPROTO_ICMPV6) {
        return @intFromEnum(Xdp.RET.pass);
    } else if (ipv6hdr.nxt == IPPROTO_TCP) {
        const tcpHdr: *const TcpHdr = ctx.get_ptr(TcpHdr, iphdr_offset + (10 * 4)) orelse return @intFromEnum(Xdp.RET.aborted);
        if (!(tcpHdr.syn == 1 and tcpHdr.ack == 0)) {
            return @intFromEnum(Xdp.RET.pass);
        }

        const acl_key = AclKey{
            .ip_src_addr = In6Addr{ .in6_u = .{ .u6_addr8 = ipv6hdr.src } },
            .ip_proto = ipv6hdr.nxt,
            .dst_port = tcpHdr.dest,
            .reserved = 0,
        };

        const acl_val = acl_map.lookup(acl_key);
        if (acl_val) |val| {
            val.* += 1;
            return @intFromEnum(Xdp.RET.pass);
        } else {
            return @intFromEnum(Xdp.RET.drop);
        }
    } else if (ipv6hdr.nxt == IPPROTO_UDP) {
        const udpHdr: *const UdpHdr = ctx.get_ptr(UdpHdr, iphdr_offset + (10 * 4)) orelse return @intFromEnum(Xdp.RET.aborted);

        const acl_key = AclKey{
            .ip_src_addr = In6Addr{ .in6_u = .{ .u6_addr8 = ipv6hdr.src } },
            .ip_proto = ipv6hdr.nxt,
            .dst_port = udpHdr.dest,
            .reserved = 0,
        };

        const acl_val = acl_map.lookup(acl_key);
        if (acl_val) |val| {
            val.* += 1;
            return @intFromEnum(Xdp.RET.pass);
        } else {
            return @intFromEnum(Xdp.RET.drop);
        }
    } else {
        return @intFromEnum(Xdp.RET.drop);
    }
}

pub fn u32_to_bytes(num: u32) [4]u8 {
    return [4]u8{
        @truncate(num),
        @truncate(num >> 8),
        @truncate(num >> 16),
        @truncate(num >> 24),
    };
}
