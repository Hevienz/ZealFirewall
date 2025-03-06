const __u8 = u8;
const __be16 = u16;
const __be32 = u32;
const __sum16 = u16;
const __u16 = u16;

pub const In6Addr = extern struct {
    in6_u: extern union {
        u6_addr8: [16]__u8,
        u6_addr16: [8]__be16,
        u6_addr32: [4]__be32,
    },
};

pub const AclKey = struct {
    ip_src_addr: In6Addr,
    dst_port: u16,
    ip_proto: u8,
    reserved: u8,
};
