const std = @import("std");
const ManagedArrayList = std.array_list.Managed;

const MAX_PENDING: usize = 100;
const MAX_PACKET: u64 = 131072;

const ModuleChain = extern struct {
    ctx: *anyopaque,
    request_outputs: *const fn (*anyopaque, c_int) callconv(.c) c_int,
    get_output_fd: *const fn (*anyopaque, c_int) callconv(.c) c_int,
    get_node_id: *const fn (*anyopaque) callconv(.c) c_int,
    write_packet: *const fn (*anyopaque, c_int, [*]const u8, usize) callconv(.c) c_int,
    request_heartbeat: *const fn (*anyopaque, c_int) callconv(.c) c_int,
    set_src: *const fn (*anyopaque, c_int) callconv(.c) void,
};

extern fn free(ptr: ?*anyopaque) void;

fn now_ns() i128 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * 1_000_000_000 + @as(i128, @intCast(ts.nsec));
}

const PendingPacket = struct {
    data: [*]const u8,
    len: usize,
    src_idx: c_int,
};

const TokenBucket = struct {
    rate_bps: u64,
    burst: f64,
    tokens: f64,
    last_ns: i128,

    fn init(rate_bps: u64, burst_bytes: u64) TokenBucket {
        return .{
            .rate_bps = rate_bps,
            .burst = @floatFromInt(burst_bytes),
            .tokens = @floatFromInt(burst_bytes),
            .last_ns = now_ns(),
        };
    }

    fn refill(self: *TokenBucket) void {
        const now = now_ns();
        const elapsed_ns = now - self.last_ns;
        if (elapsed_ns <= 0) return;
        const rate_per_ns = @as(f64, @floatFromInt(self.rate_bps)) / 8.0 / 1_000_000_000.0;
        self.tokens += rate_per_ns * @as(f64, @floatFromInt(elapsed_ns));
        self.last_ns = now;
    }

    fn try_consume(self: *TokenBucket, bytes: u64) bool {
        self.refill();
        const needed = @as(f64, @floatFromInt(bytes));
        if (self.tokens >= needed) {
            self.tokens -= needed;
            return true;
        }
        return false;
    }
};

const LimitCtx = struct {
    api: *ModuleChain,
    node_id: c_int,
    trace: bool,
    buckets: [2]TokenBucket,
    dir_mask: u2,
    pending: [2]ManagedArrayList(PendingPacket),
    allocator: std.mem.Allocator = undefined,
    have_heartbeat: bool,
};

const dir_bits: [2]u2 = .{ 1, 2 };

fn drain_dir(ctx: *LimitCtx, udir: usize) void {
    if (dir_bits[udir] & ctx.dir_mask == 0) return;
    var bucket = &ctx.buckets[udir];
    while (ctx.pending[udir].items.len > 0) {
        const pp = ctx.pending[udir].items[0];
        if (!bucket.try_consume(pp.len)) break;
        _ = ctx.pending[udir].orderedRemove(0);
        ctx.api.set_src(ctx.api.ctx, pp.src_idx);
        const write_dst: c_int = if (udir == 0) 1 else 0;
        _ = ctx.api.write_packet(ctx.api.ctx, write_dst, pp.data, pp.len);
    }
}

fn update_heartbeat(ctx: *LimitCtx) void {
    const has_pending = ctx.pending[0].items.len > 0 or ctx.pending[1].items.len > 0;
    if (has_pending and !ctx.have_heartbeat) {
        _ = ctx.api.request_heartbeat(ctx.api.ctx, 0);
        ctx.have_heartbeat = true;
    } else if (!has_pending and ctx.have_heartbeat) {
        _ = ctx.api.request_heartbeat(ctx.api.ctx, -1);
        ctx.have_heartbeat = false;
    }
}

export fn init(api: ?*ModuleChain, config: ?[*:0]const u8) callconv(.c) ?*anyopaque {
    const c_api = api orelse return null;

    var rate_bps: u64 = 1_000_000;
    var burst_bytes: u64 = 0;
    var trace: bool = false;
    var dm: u2 = 3;

    if (config) |cfg| {
        const s = std.mem.sliceTo(cfg, 0);
        var it = std.mem.splitScalar(u8, s, ',');
        while (it.next()) |token| {
            if (std.mem.eql(u8, token, "trace")) {
                trace = true;
                continue;
            }
            if (std.mem.indexOfScalar(u8, token, ':')) |colon| {
                const key = token[0..colon];
                const val = token[colon + 1 ..];
                if (std.mem.eql(u8, key, "rate")) {
                    rate_bps = parse_suffix_int(val, 1000) catch 1_000_000;
                } else if (std.mem.eql(u8, key, "b")) {
                    burst_bytes = parse_suffix_int(val, 1024) catch 0;
                } else if (std.mem.eql(u8, key, "dir")) {
                    const d = std.fmt.parseInt(u3, val, 10) catch 3;
                    dm = @as(u2, @intCast(d & 3));
                }
            }
        }
    }

    if (burst_bytes == 0)
        burst_bytes = @max(rate_bps / 80, MAX_PACKET);

    const allocator = std.heap.page_allocator;
    const buf = allocator.create(LimitCtx) catch return null;
    buf.* = .{
        .api = c_api,
        .node_id = c_api.get_node_id(c_api.ctx),
        .trace = trace,
        .buckets = .{
            TokenBucket.init(rate_bps, burst_bytes),
            TokenBucket.init(rate_bps, burst_bytes),
        },
        .dir_mask = dm,
        .pending = .{
            ManagedArrayList(PendingPacket).init(allocator),
            ManagedArrayList(PendingPacket).init(allocator),
        },
        .allocator = allocator,
        .have_heartbeat = false,
    };

    if (trace) {
        std.debug.print("[limit node={d} init] rate={d} bps burst={d} dir={d}\n", .{ buf.node_id, rate_bps, burst_bytes, dm });
    }

    return buf;
}

export fn process(ctx_ptr: ?*anyopaque, dir: c_int, trigger_idx: c_int, data: [*]const u8, len: usize) callconv(.c) c_int {
    const ctx = @as(*LimitCtx, @ptrCast(@alignCast(ctx_ptr orelse return -1)));
    const src_idx = trigger_idx;

    if (dir < 0) {
        // heartbeat tick — refill + drain both dirs
        ctx.buckets[0].refill();
        ctx.buckets[1].refill();
        drain_dir(ctx, 0);
        drain_dir(ctx, 1);
        update_heartbeat(ctx);
        return 0;
    }

    const udir = @as(usize, @intCast(dir));
    if (udir > 1) return 0;
    if (dir_bits[udir] & ctx.dir_mask == 0) return 0;

    if (len == 0) return -1;

    // Try to consume tokens immediately
    if (ctx.buckets[udir].try_consume(len)) {
        const write_dst: c_int = if (dir == 0) 1 else 0;
        return ctx.api.write_packet(ctx.api.ctx, write_dst, data, len);
    }

    // No tokens — queue or drop
    if (ctx.pending[udir].items.len >= MAX_PENDING) {
        if (ctx.trace) {
            std.debug.print("[limit node={d}] DROP dir={d} len={d} pending={d}\n", .{ ctx.node_id, dir, len, ctx.pending[udir].items.len });
        }
        const p_free: [*]u8 = @constCast(data);
        free(@as(?*anyopaque, @ptrCast(p_free)));
        return 0;
    }

    ctx.pending[udir].append(.{ .data = @constCast(data), .len = len, .src_idx = src_idx }) catch {
        const p_free2: [*]u8 = @constCast(data);
        free(@as(?*anyopaque, @ptrCast(p_free2)));
        return 0;
    };

    update_heartbeat(ctx);

    if (ctx.trace) {
        std.debug.print("[limit node={d}] QUEUE dir={d} len={d} pending={d}\n", .{ ctx.node_id, dir, len, ctx.pending[udir].items.len });
    }

    return 0;
}

fn parse_suffix_int(s: []const u8, multiplier: u64) !u64 {
    if (s.len == 0) return error.Empty;
    if (std.fmt.parseInt(u64, s, 10)) |v| return v else |_| {}
    if (s.len < 2) return error.Invalid;
    const val = try std.fmt.parseInt(u64, s[0 .. s.len - 1], 10);
    switch (std.ascii.toLower(s[s.len - 1])) {
        'k' => return val * multiplier,
        'm' => return val * multiplier * multiplier,
        'g' => return val * multiplier * multiplier * multiplier,
        else => return error.Invalid,
    }
}

export fn modulename() callconv(.c) [*:0]const u8 {
    return "limit";
}

export fn moduleversion() callconv(.c) [*:0]const u8 {
    return "2.0.0";
}

export fn moduledesc() callconv(.c) [*:0]const u8 {
    return "Rate limiter with async token bucket and pending queue";
}

export fn modulehelp() callconv(.c) [*:0]const u8 {
    return "Async rate limiter. Queues packets when tokens unavailable, drains via heartbeat.\nConfig: rate:N[kmg],b:N[km],dir:0|1|2,trace\n  rate - bits/sec (k=1000, m=1e6, g=1e9)\n  b    - burst bytes (k=1024, m=1024^2, default=max(rate/80,131072))\n  dir  - 0=ext->wire, 1=wire->ext, 2=both (default=2)\n  trace - debug logging to stderr";
}
