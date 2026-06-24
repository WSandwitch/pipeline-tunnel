#include "modules/include/module_api.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <map>

#define CLAMP(x,lo,hi) ((x) < (lo) ? (lo) : (x) > (hi) ? (hi) : (x))

#define DEF_CHUNK_SIZE 16384
#define MIN_CHUNK 64
#define MAX_CHUNK 65536
#define HEADER_SIZE 4
#define MAX_CHUNKS_PER_PASS 65536

struct SlotEntry {
    uint8_t *data;
    uint32_t size;
    uint8_t more;
};

struct SplitContext {
    ModuleChain *api = nullptr;
    int num_outputs = 1;
    uint32_t rr_idx = 0;
    uint32_t pkt_seq = 0;
    uint32_t chunk_idx = 0;
    std::map<uint64_t, SlotEntry> pending;
    uint32_t exp_pkt = 0;
    uint32_t exp_chunk = 0;
    int trace = 0;
    int chunk_size_min = DEF_CHUNK_SIZE;
    int chunk_size_max = DEF_CHUNK_SIZE;
    uint64_t chunks_created = 0;    // split: total chunks output
    uint64_t chunks_received = 0;   // merge: total chunks received
    uint64_t packets_created = 0;   // split: total packets split
    uint64_t packets_flushed = 0;   // merge: total packets merged
    uint64_t chunks_lost = 0;       // merge: chunks orphaned by pkt wrap
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

static uint32_t encode_hdr(uint32_t pkt_id, uint16_t more, uint16_t chunk_id) {
    return (uint32_t)(pkt_id & 0x7FFF)
         | ((uint32_t)(more ? 1 : 0) << 15)
         | ((uint32_t)chunk_id << 16);
}

static int process_split(SplitContext *ctx, int trigger_idx, const uint8_t *data, size_t len) {
    if (!data || len <= 0) {
        if (ctx->trace) std::fprintf(stderr, "[SPLIT] dir=0 IN sz=%zu trigger=%d pkt=%u chunk=%u outputs=%d\n", len, trigger_idx, ctx->pkt_seq, ctx->chunk_idx, ctx->num_outputs);
        return 0;
    }

    if (ctx->trace) std::fprintf(stderr, "[SPLIT] dir=0 IN sz=%zu trigger=%d pkt=%u chunk=%u outputs=%d\n", len, trigger_idx, ctx->pkt_seq, ctx->chunk_idx, ctx->num_outputs);
    int sz = (int)len;
    const uint8_t *in_buf = data;
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

        uint32_t hdr_val = encode_hdr(ctx->pkt_seq, more, ctx->chunk_idx);

        int out_idx = 1 + (int)(ctx->rr_idx % (uint32_t)ctx->num_outputs);
        uint8_t *out_buf = (uint8_t *)ctx->api->malloc(ctx->api->ctx, (size_t)(chunk_len + HEADER_SIZE));
        if (!out_buf) {
            ctx->api->free(ctx->api->ctx, (void*)data);
            return 0;
        }
        out_buf[0] = (uint8_t)(hdr_val & 0xFF);
        out_buf[1] = (uint8_t)((hdr_val >> 8) & 0xFF);
        out_buf[2] = (uint8_t)((hdr_val >> 16) & 0xFF);
        out_buf[3] = (uint8_t)((hdr_val >> 24) & 0xFF);
        std::memcpy(out_buf + HEADER_SIZE, in_buf + offset, (size_t)chunk_len);

        int wpret = ctx->api->write_packet(ctx->api->ctx, out_idx,
                               out_buf, (size_t)(chunk_len + HEADER_SIZE));
        if (wpret < 0 && ctx->trace)
            std::fprintf(stderr, "[SPLIT] OUT FAIL pkt=%u out=%d ret=%d\n", ctx->pkt_seq, out_idx, wpret);
        ctx->rr_idx++;
        ctx->chunk_idx++;
        offset += chunk_len;
        chunks++;
    }

    ctx->packets_created++;
    ctx->chunks_created += chunks;
    if (ctx->trace) std::fprintf(stderr, "[SPLIT] PKT_END seq=%u chunks=%d total_chunks=%lu\n",
                ctx->pkt_seq, chunks, (unsigned long)ctx->chunks_created);

    ctx->pkt_seq++;
    ctx->chunk_idx = 0;

    ctx->api->free(ctx->api->ctx, (void*)data);
    return 0;
}

static int process_merge(SplitContext *ctx, int trigger_idx, const uint8_t *data, size_t len) {
    if (!data || len <= 0) {
        if (ctx->trace) std::fprintf(stderr, "[MERGE] dir=1 IN sz=%zu trigger=%d exp_pkt=%u exp_chunk=%u\n", len, trigger_idx, ctx->exp_pkt, ctx->exp_chunk);
        return 0;
    }

    if (len < HEADER_SIZE) {
        ctx->api->free(ctx->api->ctx, (void*)data);
        return 0;
    }
    uint32_t hdr = (uint32_t)data[0]
                 | ((uint32_t)data[1] << 8)
                 | ((uint32_t)data[2] << 16)
                 | ((uint32_t)data[3] << 24);
    uint16_t wire_id = (uint16_t)(hdr & 0x7FFF);
    uint16_t more = (uint16_t)((hdr >> 15) & 1);
    uint16_t chunk_id = (uint16_t)((hdr >> 16) & 0xFFFF);

    // seq32 extension: expand 15-bit wire_id to full 32-bit sequence
    uint32_t pkt_full = (ctx->exp_pkt & ~0x7FFF) | wire_id;
    if (pkt_full + 16384 < ctx->exp_pkt)
        pkt_full += 32768;
    else if (pkt_full >= ctx->exp_pkt + 16384)
        pkt_full -= 32768;

    const uint8_t *payload = data + HEADER_SIZE;
    int payload_len = (int)(len - HEADER_SIZE);

    if (ctx->trace) std::fprintf(stderr, "[MERGE] RECV pkt=%u (wire=%u) chunk=%u more=%d len=%d trigger=%d exp_pkt=%u exp_chunk=%u\n",
                pkt_full, wire_id, chunk_id, more, payload_len, trigger_idx, ctx->exp_pkt, ctx->exp_chunk);

    // Detect orphan: chunk belongs to a packet before exp_pkt (will never be flushed)
    if (pkt_full < ctx->exp_pkt) {
        if (ctx->trace)
            std::fprintf(stderr, "[MERGE] ORPHAN pkt=%u (wire=%u) chunk=%u (exp_pkt=%u) — LOST!\n",
                    pkt_full, wire_id, chunk_id, ctx->exp_pkt);
        ctx->chunks_lost++;
        ctx->api->free(ctx->api->ctx, (void*)data);
        return 0;
    }

    uint64_t key = ((uint64_t)pkt_full << 16) | chunk_id;

    auto it = ctx->pending.find(key);
    if (it != ctx->pending.end()) {
        ctx->api->free(ctx->api->ctx, it->second.data);
        ctx->pending.erase(it);
    }

    SlotEntry &se = ctx->pending[key];
    se.data = (uint8_t *)ctx->api->malloc(ctx->api->ctx, (size_t)payload_len);
    std::memcpy(se.data, payload, (size_t)payload_len);
    se.size = (uint32_t)payload_len;
    se.more = more;

    ctx->chunks_received++;

    int write_output = 0;

    while (true) {
        uint64_t exp_key = ((uint64_t)ctx->exp_pkt << 16) | ctx->exp_chunk;
        auto ei = ctx->pending.find(exp_key);
        if (ei == ctx->pending.end()) break;

        if (!ei->second.more) {
            size_t total = 0;
            uint64_t start_key = ((uint64_t)ctx->exp_pkt << 16);
            uint64_t end_key = exp_key;
            for (auto ki = ctx->pending.lower_bound(start_key); ki != ctx->pending.end() && ki->first <= end_key; ++ki) {
                total += ki->second.size;
            }

            if (ctx->trace) std::fprintf(stderr, "[MERGE] FLUSH pkt=%u chunks=0..%u size=%zu\n",
                    ctx->exp_pkt, ctx->exp_chunk, total);

            uint8_t *out_buf = (uint8_t *)ctx->api->malloc(ctx->api->ctx, total);
            if (out_buf) {
                size_t off = 0;
                for (auto ki = ctx->pending.lower_bound(start_key); ki != ctx->pending.end() && ki->first <= end_key; ) {
                    std::memcpy(out_buf + off, ki->second.data, ki->second.size);
                    off += ki->second.size;
                    ctx->api->free(ctx->api->ctx, ki->second.data);
                    ki = ctx->pending.erase(ki);
                }
                ctx->api->write_packet(ctx->api->ctx, write_output, out_buf, total);
                ctx->packets_flushed++;
                if (ctx->trace)
                    std::fprintf(stderr, "[MERGE] FLUSH pkt=%u chunks=%u size=%zu pending=%zu\n",
                            ctx->exp_pkt, ctx->exp_chunk+1, total, ctx->pending.size());
            }

            ctx->exp_pkt++;
            ctx->exp_chunk = 0;
            continue;
        }

        ctx->exp_chunk++;
    }

    ctx->api->free(ctx->api->ctx, (void*)data);
    return 0;
}

extern "C" {

void *init(ModuleChain *api, const char *config) {
    SplitContext *ctx = new SplitContext();
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

        if (std::strstr(config, "n:") != NULL)
            extra_outputs = std::atoi(std::strstr(config, "n:") + 2);
        else if (std::strncmp(config, "split:", 6) == 0)
            extra_outputs = std::atoi(config + 6);
        else if (std::strcmp(config, "split") == 0)
            extra_outputs = 1;
    }
    if (extra_outputs < 1) extra_outputs = 1;

    if (api && api->request_outputs) {
        int extras_needed = (extra_outputs > 1) ? (extra_outputs - 1) : 0;
        int ret = api->request_outputs(api->ctx, extras_needed);
        (void)ret;
        ctx->num_outputs = extra_outputs;
    } else {
        ctx->num_outputs = 1;
    }

    ctx->trace = (config && std::strstr(config, "trace") != NULL) ? 1 : 0;

    if (ctx->chunk_size_min < ctx->chunk_size_max)
        std::srand((unsigned)(std::time(nullptr) ^ (uintptr_t)ctx));

    return ctx;
}

int process(void *ctx_ptr, int dir, int trigger_idx, const uint8_t *data, size_t len) {
    SplitContext *ctx = (SplitContext *)ctx_ptr;
    if (dir == 0)
        return process_split(ctx, trigger_idx, data, len);
    else {
        return process_merge(ctx, trigger_idx, data, len);
    }
}

const char *moduleversion(void) {
    return "1.0.3";
}

const char *modulename(void) {
    return "split";
}

const char *moduledesc(void) {
    return "Split/merge module for multi-stream data transfer";
}

const char *modulehelp(void) {
    return "Splits large packets into chunks (round-robin), merges by pkt_id+chunk_id.\n"
           "Config: \"n:N\" for N extra streams (default 1).\n"
           "        \"s:SIZE\" fixed chunk size, \"s:MIN-MAX\" random range (suffix K).\n"
           "        \"trace\" enables debug output.\n"
           "Default chunk size: 16384, min 64, max 65536. 4-byte header: 15b pkt_id + 1b more + 16b chunk_id, seq32 wraps.";
}

} // extern "C"
