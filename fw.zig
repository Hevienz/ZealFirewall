const std = @import("std");
const print = std.debug.print;
pub const libbpf = @cImport({
    @cInclude("libbpf.h");
    @cInclude("bpf.h");
    @cInclude("btf.h");
});
const c = @cImport({
    @cInclude("net/if.h");
    @cInclude("linux/if_link.h");
});
const httpz = @import("httpz");
const yazap = @import("yazap");
const acl_key = @import("acl_key.zig");
const net = std.net;
const mem = std.mem;
const binary = std.binary;

const debug = false;
var should_exit = std.atomic.Value(bool).init(false);
var acl_map: *libbpf.struct_bpf_map = undefined;

pub fn dbg_printf(level: libbpf.libbpf_print_level, fmt: [*c]const u8, args: @typeInfo(@typeInfo(@typeInfo(libbpf.libbpf_print_fn_t).optional.child).pointer.child).@"fn".params[2].type.?) callconv(.C) c_int {
    if (!debug and level == libbpf.LIBBPF_DEBUG) return 0;

    return libbpf.vdprintf(std.io.getStdErr().handle, fmt, args);
}

fn signal_handler(_: c_int) align(1) callconv(.C) void {
    std.debug.print("Received SIGINT\n", .{});

    should_exit.store(true, .seq_cst);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    defer {
        const deinit_status = gpa.deinit();

        if (deinit_status == .leak) @panic("TEST FAIL");
    }

    var app = yazap.App.init(allocator, "ZealFirewall", "A eBPF firewall written in Zig");
    defer app.deinit();

    var myfw = app.rootCommand();

    try myfw.addArg(yazap.Arg.singleValueOption("ifname", 'i', "Network interface name"));

    const matches = try app.parseProcess();

    if (matches.getSingleValue("ifname") == null) {
        print("Please specify an network interface name.\n\n\n", .{});
        try app.displayHelp();
        return error.NO_IFNAME;
    }
    const ifname = matches.getSingleValue("ifname").?;

    var sa = std.posix.Sigaction{
        .handler = .{
            .handler = &signal_handler,
        },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    const bytes = @embedFile("@bpf_prog");

    _ = libbpf.libbpf_set_print(dbg_printf);

    const obj = libbpf.bpf_object__open_mem(bytes.ptr, bytes.len, null);
    if (obj == null) {
        print("failed to open bpf object: {}\n", .{std.posix.errno(-1)});
        return error.OPEN;
    }
    defer libbpf.bpf_object__close(obj);

    var ret = libbpf.bpf_object__load(obj);
    if (ret != 0) {
        print("failed to load bpf object: {}\n", .{std.posix.errno(-1)});
        return error.LOAD;
    }

    const prog = libbpf.bpf_object__find_program_by_name(obj, "firewall").?;
    acl_map = libbpf.bpf_object__find_map_by_name(obj, "acl_map").?;

    const idx = c.if_nametoindex(@ptrCast(ifname));
    if (idx == 0) {
        print("failed to get index of lo: {}\n", .{std.posix.errno(-1)});
        return error.DEV;
    }

    const prog_fd = libbpf.bpf_program__fd(prog);
    ret = libbpf.bpf_xdp_attach(@intCast(idx), prog_fd, c.XDP_FLAGS_UPDATE_IF_NOEXIST, null);
    if (ret < 0) {
        print("failed to attach program: {}\n", .{std.posix.errno(-1)});
        return error.ATTACH;
    }
    defer _ = libbpf.bpf_xdp_detach(@intCast(idx), c.XDP_FLAGS_UPDATE_IF_NOEXIST, null);

    var key = acl_key.AclKey{
        .ip_src_addr = acl_key.In6Addr{
            .in6_u = .{
                .u6_addr8 = [16]u8{
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1,
                },
            },
        },
        .dst_port = std.mem.nativeToBig(u16, 8369),
        .ip_proto = 6,
        .reserved = 0,
    };
    var value: u64 = 0;

    ret = libbpf.bpf_map__update_elem(acl_map, &key, @sizeOf(acl_key.AclKey), &value, @sizeOf(@TypeOf(value)), 0);
    if (ret != 0) {
        print("failed to update map element: {}\n", .{std.posix.errno(-1)});
        return error.MAP_UPDATE;
    }

    _ = try std.Thread.spawn(.{}, run, .{});

    while (!should_exit.load(.seq_cst)) {
        std.debug.print("Working...\n", .{});
        std.time.sleep(1 * std.time.ns_per_s);
    }

    std.debug.print("Exiting gracefully...\n", .{});
}

pub fn u32_to_bytes(num: u32) [4]u8 {
    return [4]u8{
        @truncate(num),
        @truncate(num >> 8),
        @truncate(num >> 16),
        @truncate(num >> 24),
    };
}

pub fn run() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    defer {
        const deinit_status = gpa.deinit();

        if (deinit_status == .leak) @panic("TEST FAIL");
    }

    var server = try httpz.Server(void).init(allocator, .{ .port = 8369 }, {});
    defer {
        // clean shutdown, finishes serving any live request
        server.stop();
        server.deinit();
    }

    const cors = try server.middleware(httpz.middleware.Cors, .{
        .origin = "http://127.0.0.1:5374/",
    });

    const router = try server.router(.{ .middlewares = &.{cors} });

    var group = router.group("/api/v1", .{});

    group.post("/rules", addRule, .{});

    group.get("/rule", getRule, .{});

    group.delete("/rule", deleteRule, .{});

    group.get("/rules", getRules, .{});

    try server.listen();
}

const Key = struct {
    src_addr: []const u8,
    dst_port: u16,
    ip_proto: u8,

    fn toAclKey(self: Key) !acl_key.AclKey {
        const a = try net.Address.parseIp(self.src_addr, 0);

        if (a.any.family == std.posix.AF.INET) {
            const a_bytes = u32_to_bytes(a.in.sa.addr);

            return acl_key.AclKey{
                .ip_src_addr = acl_key.In6Addr{
                    .in6_u = .{
                        .u6_addr8 = [16]u8{
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, a_bytes[0], a_bytes[1], a_bytes[2], a_bytes[3],
                        },
                    },
                },
                .dst_port = std.mem.nativeToBig(u16, self.dst_port),
                .ip_proto = self.ip_proto,
                .reserved = 0,
            };
        } else if (a.any.family == std.posix.AF.INET6) {
            return acl_key.AclKey{
                .ip_src_addr = acl_key.In6Addr{
                    .in6_u = .{
                        .u6_addr8 = a.in6.sa.addr,
                    },
                },
                .dst_port = std.mem.nativeToBig(u16, self.dst_port),
                .ip_proto = self.ip_proto,
                .reserved = 0,
            };
        } else {
            return error.UnsupportedFamily;
        }
    }
};

fn addRule(req: *httpz.Request, res: *httpz.Response) !void {
    if (req.json(Key)) |k| {
        if (k.?.toAclKey()) |ak| {
            var value: u64 = 0;

            const ret = libbpf.bpf_map__update_elem(acl_map, &ak, @sizeOf(acl_key.AclKey), &value, @sizeOf(@TypeOf(value)), 0);
            if (ret != 0) {
                print("failed to update map element: {}\n", .{std.posix.errno(-1)});
                try res.json(.{ .code = 500, .msg = "add rule failed" }, .{});
            } else {
                try res.json(.{ .code = 200 }, .{});
            }
        } else |err| {
            try res.json(.{ .code = 400, .msg = err }, .{});
        }
    } else |err| {
        try res.json(.{ .code = 400, .msg = err }, .{});
    }
}

fn getRule(req: *httpz.Request, res: *httpz.Response) !void {
    if (req.json(Key)) |k| {
        if (k.?.toAclKey()) |ak| {
            var value: u64 = 0;

            const ret = libbpf.bpf_map__lookup_elem(acl_map, &ak, @sizeOf(acl_key.AclKey), &value, @sizeOf(@TypeOf(value)), 0);
            if (ret != 0) {
                print("failed to lookup map element: {}\n", .{std.posix.errno(-1)});
                try res.json(.{ .code = 500, .msg = "get rule failed" }, .{});
            } else {
                try res.json(.{ .code = 200, .data = value }, .{});
            }
        } else |err| {
            try res.json(.{ .code = 400, .msg = err }, .{});
        }
    } else |err| {
        try res.json(.{ .code = 400, .msg = err }, .{});
    }
}

fn deleteRule(req: *httpz.Request, res: *httpz.Response) !void {
    if (req.json(Key)) |k| {
        if (k.?.toAclKey()) |ak| {
            const ret = libbpf.bpf_map__delete_elem(acl_map, &ak, @sizeOf(acl_key.AclKey), 0);
            if (ret != 0) {
                print("failed to delete map element: {}\n", .{std.posix.errno(-1)});
                try res.json(.{ .code = 500, .msg = "get rule failed" }, .{});
            } else {
                try res.json(.{ .code = 200 }, .{});
            }
        } else |err| {
            try res.json(.{ .code = 400, .msg = err }, .{});
        }
    } else |err| {
        try res.json(.{ .code = 400, .msg = err }, .{});
    }
}

const KV = struct {
    key: []const u8,
    value: u64,
};

const MyStruct = struct {
    list: std.ArrayList(KV),

    const Self = @This();

    pub fn jsonStringify(self: Self, out: anytype) !void {
        try out.beginObject();
        try out.objectField("list");
        try out.write(self.list.items);
        try out.endObject();
    }
};

fn getRules(req: *httpz.Request, res: *httpz.Response) !void {
    var prev_ak: acl_key.AclKey = undefined;
    var ak: acl_key.AclKey = undefined;

    var my_struct = MyStruct{
        .list = std.ArrayList(KV).init(req.arena),
    };
    defer my_struct.list.deinit();

    while (true) {
        var ret = libbpf.bpf_map__get_next_key(acl_map, &prev_ak, &ak, @sizeOf(acl_key.AclKey));
        if (ret != 0) {
            break;
        }

        var value: u64 = 0;
        ret = libbpf.bpf_map__lookup_elem(acl_map, &ak, @sizeOf(acl_key.AclKey), &value, @sizeOf(@TypeOf(value)), 0);
        if (ret != 0) {
            print("failed to lookup map element: {}\n", .{std.posix.errno(-1)});
            return try res.json(.{ .code = 500, .msg = "get rule failed" }, .{});
        }

        const a = std.net.Address.initIp6(ak.ip_src_addr.in6_u.u6_addr8, std.mem.bigToNative(u16, ak.dst_port), 0, 0);

        var buffer: [100]u8 = undefined;
        const a_str = try std.fmt.bufPrint(buffer[0..], "{} {}", .{ a, ak.ip_proto });

        const kv = KV{
            .key = a_str,
            .value = value,
        };

        try my_struct.list.append(kv);

        prev_ak = ak;
    }

    try res.json(.{ .code = 200, .data = my_struct }, .{});
}
