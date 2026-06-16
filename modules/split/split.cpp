#include "modules/include/module_api.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <vector>

#define CLAMP(x,lo,hi) ((x) < (lo) ? (lo) : (x) > (hi) ? (hi) : (x))

#define DEF_CHUNK_SIZE 16384
#define MIN_CHUNK 64
#define MAX_CHUNK 65536
#define HEADER_SIZE 5
#define MAX_CHUNKS_PER_PASS 65536
#define RING_SIZE 65536
#define RING_MASK (RING_SIZE - 1)

struct SlotEntry {
    uint8_t *data;
    uint32_t size;
    uint16_t seq_high;
    uint8_t flags;
};

struct SplitContext {
    ModuleChain *api = nullptr;
    int num_outputs = 1;
    uint32_t rr_idx = 0;
    uint32_t seqnum = 0;
    uint32_t merge_next_seq = 0;
    std::vector<SlotEntry> ring;
    int trace = 0;
    int node_id = -1;
    int chunk_size_min = DEF_CHUNK_SIZE;
    int chunk_size_max = DEF_CHUNK_SIZE;
};

static int parse_size(const char *s, int def) {
    if (!s || !*s) return def;
    long val = std::atol(s);
    if (val <= 0) return def;
    size_t len = std::strlen(s);
    if (len > 0 && (s[len-1] == 'K' || s[len-1] == 'k'))
        val *= 1024;
    return CLAMP((int)val, MIN_CHUNK, MAX_CHUNK);
}

static int next_chunk_size(SplitContext *ctx) {
    int lo = ctx->chunk_size_min;
    int hi = ctx->chunk_size_max;
    if (lo >= hi) return lo;
    return lo + (int)((unsigned)std::rand() % (unsigned)(hi - lo + 1));
}

static int process_split(SplitContext *ctx, int trigger_idx) {
    int sz = 0;
    uint8_t *in_buf = (uint8_t *)ctx->api->get_packet(ctx->api->ctx, 0, &sz);
    if (!in_buf || sz <= 0) {
        if (ctx->trace) std::fprintf(stderr, "[SPLIT] dir=0 IN sz=%d trigger=%d rr_idx=%u seqnum=%u outputs=%d\n", sz, trigger_idx, ctx->rr_idx, ctx->seqnum, ctx->num_outputs);
        return 0;
    }

    if (ctx->trace) std::fprintf(stderr, "[SPLIT] dir=0 IN sz=%d trigger=%d rr_idx=%u seqnum=%u outputs=%d\n", sz, trigger_idx, ctx->rr_idx, ctx->seqnum, ctx->num_outputs);

    int offset = 0;
    int chunks = 0;

    while (offset < sz) {
        int remain = sz - offset;
        int chunk_len;
        if (chunks >= MAX_CHUNKS_PER_PASS - 1) {
            chunk_len = remain;
        } else {
            chunk_len = next_chunk_size(ctx);
            if (chunk_len > remain) chunk_len = remain;
        }
        int more = (offset + chunk_len < sz) ? 1 : 0;

        uint8_t header[HEADER_SIZE];
        header[0] = (uint8_t)(ctx->seqnum & 0xFF);
        header[1] = (uint8_t)((ctx->seqnum >> 8) & 0xFF);
        header[2] = (uint8_t)((ctx->seqnum >> 16) & 0xFF);
        header[3] = (uint8_t)((ctx->seqnum >> 24) & 0xFF);
        header[4] = (uint8_t)more;

        int out_idx = 1 + (int)(ctx->rr_idx % (uint32_t)ctx->num_outputs);
        uint8_t *out_buf = (uint8_t *)std::malloc((size_t)(chunk_len + HEADER_SIZE));
        if (!out_buf) {
            std::free(in_buf);
            return 0;
        }
        std::memcpy(out_buf, header, HEADER_SIZE);
        std::memcpy(out_buf + HEADER_SIZE, in_buf + offset, (size_t)chunk_len);

        if (ctx->trace) std::fprintf(stderr, "[SPLIT] OUT seq=%u more=%d out=%d len=%d offset=%d/%d remain=%d\n",
                ctx->seqnum, more, out_idx, chunk_len, offset, sz, remain - chunk_len);
        ctx->api->write_packet(ctx->api->ctx, out_idx,
                               out_buf, (size_t)(chunk_len + HEADER_SIZE));
        ctx->rr_idx++;
        ctx->seqnum++;
        offset += chunk_len;
        chunks++;
    }

    std::free(in_buf);
    return 0;
}

static int process_merge(SplitContext *ctx, int trigger_idx) {
    int sz = 0;
    uint8_t *buf = (uint8_t *)ctx->api->get_packet(ctx->api->ctx, 0, &sz);
    if (!buf || sz <= 0) {
        if (ctx->trace) std::fprintf(stderr, "[MERGE] dir=1 IN sz=%d trigger=%d next_seq=%u\n", sz, trigger_idx, ctx->merge_next_seq);
        return 0;
    }

    if (sz < HEADER_SIZE) { std::free(buf); return 0; }
    uint32_t seq = (uint32_t)buf[0]
                 | ((uint32_t)buf[1] << 8)
                 | ((uint32_t)buf[2] << 16)
                 | ((uint32_t)buf[3] << 24);
    int more = buf[4] ? 1 : 0;
    uint8_t *data = buf + HEADER_SIZE;
    int data_len = sz - HEADER_SIZE;

    if (ctx->trace) std::fprintf(stderr, "[MERGE] RECV seq=%u more=%d len=%d trigger=%d next_seq=%u\n",
            seq, more, data_len, trigger_idx, ctx->merge_next_seq);

    SlotEntry &s = ctx->ring[seq & RING_MASK];
    if (s.flags & 2) {
        std::free(s.data);
    }
    s.data = (uint8_t *)std::malloc((size_t)data_len);
    std::memcpy(s.data, data, (size_t)data_len);
    s.size = (uint32_t)data_len;
    s.seq_high = (uint16_t)(seq >> 16);
    s.flags = (uint8_t)((more ? 1 : 0) | 2);

    std::free(buf);

    int write_output = 0;

    uint32_t scan = ctx->merge_next_seq;
    while (true) {
        SlotEntry &es = ctx->ring[scan & RING_MASK];
        if (!(es.flags & 2)) break;
        if (!(es.flags & 1)) {
            size_t total = 0;
            for (uint32_t s = ctx->merge_next_seq; s <= scan; s++) {
                total += ctx->ring[s & RING_MASK].size;
            }

            if (ctx->trace) std::fprintf(stderr, "[MERGE] FLUSH seq=%u..%u out=%d size=%zu next=%u\n",
                    ctx->merge_next_seq, scan, write_output, total, scan + 1);

            uint8_t *out_buf = (uint8_t *)std::malloc(total);
            if (out_buf) {
                size_t off = 0;
                for (uint32_t s = ctx->merge_next_seq; s <= scan; s++) {
                    SlotEntry &cs = ctx->ring[s & RING_MASK];
                    std::memcpy(out_buf + off, cs.data, cs.size);
                    off += cs.size;
                    std::free(cs.data);
                    cs.data = nullptr;
                    cs.flags = 0;
                }
                ctx->api->write_packet(ctx->api->ctx, write_output, out_buf, total);
            }

            ctx->merge_next_seq = scan + 1;
            scan = ctx->merge_next_seq;
            continue;
        }
        scan++;
    }

    if (ctx->trace) std::fprintf(stderr, "[MERGE] WAIT next=%u\n", ctx->merge_next_seq);
    return 0;
}

extern "C" {

void *init(ModuleChain *api, const char *config) {
    SplitContext *ctx = new SplitContext();
    ctx->ring.resize(RING_SIZE);
    ctx->api = api;
    ctx->chunk_size_min = DEF_CHUNK_SIZE;
    ctx->chunk_size_max = DEF_CHUNK_SIZE;

    int extra_outputs = 1;
    if (config && config[0] != '\0') {
        const char *sp = std::strstr(config, "s:");
        if (sp) {
            sp += 2;
            const char *dash = std::strchr(sp, '-');
            if (dash) {
                char tmp[64];
                size_t len = (size_t)(dash - sp);
                if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
                std::memcpy(tmp, sp, len); tmp[len] = 0;
                ctx->chunk_size_min = parse_size(tmp, DEF_CHUNK_SIZE);
                ctx->chunk_size_max = parse_size(dash + 1, DEF_CHUNK_SIZE);
            } else {
                ctx->chunk_size_min = parse_size(sp, DEF_CHUNK_SIZE);
                ctx->chunk_size_max = ctx->chunk_size_min;
            }
            if (ctx->chunk_size_min > ctx->chunk_size_max) {
                int t = ctx->chunk_size_min;
                ctx->chunk_size_min = ctx->chunk_size_max;
                ctx->chunk_size_max = t;
            }
        }

        if (std::strncmp(config, "n:", 2) == 0)
            extra_outputs = std::atoi(config + 2);
        else if (std::strncmp(config, "split:", 6) == 0)
            extra_outputs = std::atoi(config + 6);
        else if (std::strcmp(config, "split") == 0)
            extra_outputs = 1;
    }
    if (extra_outputs < 1) extra_outputs = 1;

    if (api && api->request_outputs) {
        int ret = api->request_outputs(api->ctx, extra_outputs);
        ctx->num_outputs = ret > 0 ? ret : 1;
    } else {
        ctx->num_outputs = 1;
    }

    ctx->trace = (config && std::strstr(config, "trace") != NULL) ? 1 : 0;
    ctx->node_id = (api && api->get_node_id) ? api->get_node_id(api->ctx) : -1;

    if (ctx->chunk_size_min < ctx->chunk_size_max)
        std::srand((unsigned)(std::time(nullptr) ^ (uintptr_t)ctx));

    return ctx;
}

int process(void *ctx_ptr, int dir, int trigger_idx) {
    SplitContext *ctx = (SplitContext *)ctx_ptr;
    if (dir == 0)
        return process_split(ctx, trigger_idx);
    else
        return process_merge(ctx, trigger_idx);
}

const char *moduleversion(void) {
    return "1.0.2";
}

const char *modulename(void) {
    return "split";
}

const char *moduledesc(void) {
    return "Split/merge module for multi-stream data transfer";
}

const char *modulehelp(void) {
    return "Splits large packets into chunks (round-robin), merges by seqnum.\n"
           "Config: \"n:N\" for N extra streams (default 1).\n"
           "        \"s:SIZE\" fixed chunk size, \"s:MIN-MAX\" random range (suffix K).\n"
           "        \"trace\" enables debug output.\n"
           "Default chunk size: 16384, min 64, max 65536. 4-byte seqnum, more flag.";
}

} // extern "C"
