# Module API

## Exported Symbols

Every module `.so` must export these functions:

```c
void *init(ModuleChain *chain_api, const char *config);
int   process(void *ctx, int dir, int trigger_idx);
const char *modulename(void);
const char *moduledesc(void);
const char *modulehelp(void);
```

All five symbols are **required**.

### `init`

Called once at chain construction. Returns a module-private context pointer (passed back to `process` as `ctx`).

- `chain_api` — pointer to the `ModuleChain` vtable (see below).
- `config` — configuration string (module-defined format).

Return `NULL` on failure.

### `process`

Called when data is available.

- `dir` — direction hint (0 = forward, 1 = reverse, may be ignored).
- `trigger_idx` — 0 when data arrives on the module's input.
  The module writes the result to output 1 (or reads from input 0 and writes to output 1).
  > For multi-output modules (future), trigger_idx may differ.

Return `0` on success, negative on error.

### `modulename`, `moduledesc`, `modulehelp`

- `modulename` — short identifier (e.g. `"copy"`).
- `moduledesc` — one-line description.
- `modulehelp` — multi-line help text shown via `--module-help`.

## `ModuleChain` vtable

```c
typedef struct {
    void *ctx;
    int   (*request_outputs)(void *chain_ctx, int count);
    int   (*get_output_fd)(void *chain_ctx, int idx);
    int   (*get_node_id)(void *chain_ctx);
    void *(*get_packet)(void *chain_ctx, int idx, int *out_size);
    int   (*write_packet)(void *chain_ctx, int output_id,
                          const uint8_t *data, size_t len);
} ModuleChain;
```

### `get_packet(chain_ctx, idx, out_size)`

Returns a pointer to the next available packet and writes its size into `*out_size`.
Returns `NULL` if no packet is available. `idx == 0` means the input side.

**Ownership**: the returned pointer is owned by the module. The module must either:
- pass it to `write_packet` (transferring ownership), or
- `free()` it after use.

### `write_packet(chain_ctx, output_id, data, len)`

Writes `len` bytes from `data` to output `output_id`.

- `output_id == 0` — back to input side (e.g. reverse direction).
- `output_id == 1` — first data output (typical forward path).
- Higher values for multi-output modules (future).

**Ownership of `data` is transferred to the chain** — the module must **not** call `free(data)` after `write_packet` returns.

### `get_node_id(chain_ctx)`

Returns the system-wide unique identifier of the calling module instance.

### `request_outputs`, `get_output_fd`

Reserved for multi-output modules (e.g. `split`). Not yet implemented.

## Ownership Model — Move vs Copy

| Mode | Module does | Chain does |
|---|---|---|
| **Move** (default) | `write_packet(ctx, dst, pkt, sz)` | frees `pkt` when done |
| **Copy** | `cp = malloc(sz); memcpy(cp, pkt, sz); write_packet(ctx, dst, cp, sz); free(pkt);` | frees `cp` when done |

## Output ID convention

- `trigger_idx == 0` → data arrived on input 0 → write to output 1
- `trigger_idx == 1` → data arrived on output 1 (reverse/loopback) → write to output 0

## Config format

Config is a plain C string. Modules parse it however they like.
Convention: space-separated tokens, key-value pairs with `:` separator.

Example: `"trace m:c"` — enable tracing, copy mode.

## Build

```cmake
add_library(my_module MODULE my_module.c)
target_include_directories(my_module PRIVATE ${CMAKE_SOURCE_DIR})
set_target_properties(my_module PROPERTIES PREFIX "" SUFFIX ".so")
```

## Example: copy module

See `examples/copy_module/copy.c`.

```c
void *init(ModuleChain *api, const char *config) {
    struct copy_ctx *ctx = malloc(sizeof(*ctx));
    ctx->api = api;
    // parse config: trace, m:c/m:m
    return ctx;
}

int process(void *ctx_ptr, int dir, int trigger_idx) {
    struct copy_ctx *ctx = ctx_ptr;
    int sz;
    uint8_t *pkt = ctx->api->get_packet(ctx->api->ctx, 0, &sz);
    if (!pkt || sz <= 0) return -1;

    int write_dst = (trigger_idx == 0) ? 1 : 0;

    if (ctx->mode_copy) {
        uint8_t *cp = malloc(sz);
        memcpy(cp, pkt, sz);
        free(pkt);
        return ctx->api->write_packet(ctx->api->ctx, write_dst, cp, sz);
    } else {
        return ctx->api->write_packet(ctx->api->ctx, write_dst, pkt, sz);
    }
}
```
