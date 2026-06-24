const std = @import("std");

const ModuleChain = extern struct {
    ctx: *anyopaque,
    request_outputs: *const fn (*anyopaque, c_int) callconv(.c) c_int,
    get_output_fd: *const fn (*anyopaque, c_int) callconv(.c) c_int,
    get_node_id: *const fn (*anyopaque) callconv(.c) c_int,
    write_packet: *const fn (*anyopaque, c_int, [*]const u8, usize) callconv(.c) c_int,
    request_heartbeat: *const fn (*anyopaque, c_int) callconv(.c) c_int,
    set_src: *const fn (*anyopaque, c_int) callconv(.c) void,
};

fn now_ns() i128 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * 1_000_000_000 + @as(i128, @intCast(ts.nsec));
}

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
        if (self.tokens > self.burst)
            self.tokens = self.burst;
        self.last_ns = now;
    }

    fn consume(self: *TokenBucket, bytes: u64) void {
        self.refill();
        const needed = @as(f64, @floatFromInt(bytes));
        if (self.tokens >= needed) {
            self.tokens -= needed;
            return;
        }
        const deficit = needed - self.tokens;
        if (self.rate_bps == 0) return;
        const rate_per_ns = @as(f64, @floatFromInt(self.rate_bps)) / 8.0 / 1_000_000_000.0;
        const wait_ns = @as(u64, @intFromFloat(deficit / rate_per_ns)) + 1;
        var ts = std.os.linux.timespec{
            .sec = @as(isize, @intCast(wait_ns / 1_000_000_000)),
            .nsec = @as(isize, @intCast(wait_ns % 1_000_000_000)),
        };
        var rem: std.os.linux.timespec = undefined;
        while (std.os.linux.nanosleep(&ts, &rem) != 0) {
            ts = rem;
        }
        self.tokens = 0;
        self.last_ns = now_ns();
    }
};

const LimitCtx = struct {
    api: *ModuleChain,
    node_id: c_int,
    trace: bool,
    buckets: [2]TokenBucket,
    dir_mask: u2,
};

const dir_bits: [2]u2 = .{ 1, 2 };

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
        burst_bytes = @max(rate_bps / 80, 1);

    const buf = std.heap.page_allocator.create(LimitCtx) catch return null;
    buf.* = .{
        .api = c_api,
        .node_id = c_api.get_node_id(c_api.ctx),
        .trace = trace,
        .buckets = .{
            TokenBucket.init(rate_bps, burst_bytes),
            TokenBucket.init(rate_bps, burst_bytes),
        },
        .dir_mask = dm,
    };

    if (trace) {
        std.debug.print("[limit node={d} init] rate={d} bps burst={d} dir={d}\n", .{ buf.node_id, rate_bps, burst_bytes, dm });
    }

    return buf;
}

export fn process(ctx_ptr: ?*anyopaque, dir: c_int, trigger_idx: c_int, data: [*]const u8, len: usize) callconv(.c) c_int {
    _ = trigger_idx;
    const ctx = @as(*LimitCtx, @ptrCast(@alignCast(ctx_ptr orelse return -1)));

    if (dir < 0) return 0;

    const udir = @as(usize, @intCast(dir));
    if (udir > 1) return 0;
    if (dir_bits[udir] & ctx.dir_mask == 0) return 0;

    if (len == 0) return -1;

    ctx.buckets[udir].consume(len);

    if (ctx.trace) {
        std.debug.print("[limit node={d} dir={d} sz={d}]\n", .{ ctx.node_id, dir, len });
    }

    const write_dst: c_int = if (dir == 0) 1 else 0;
    return ctx.api.write_packet(ctx.api.ctx, write_dst, data, len);
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
    return "1.0.0";
}

export fn moduledesc() callconv(.c) [*:0]const u8 {
    return "Rate limiter with token bucket";
}

export fn modulehelp() callconv(.c) [*:0]const u8 {
    return "Limits throughput using a token bucket.\nConfig: rate:N[kmg],b:N[km],dir:0|1|2,trace\n  rate - bits/sec (k=1000, m=1e6, g=1e9)\n  b    - burst bytes (k=1024, m=1024^2, default=100ms*rate/8)\n  dir  - 0=ext->wire, 1=wire->ext, 2=both (default=2)\n  trace - debug logging to stderr";
}
