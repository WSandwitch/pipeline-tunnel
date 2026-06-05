# Module API

## Exported Symbols

Every module `.so` must export these functions:

```c
void *init(int in_fd, int out_fd, ModuleChain *chain_api, const char *config);
int   process(void *ctx, int dir, int trigger_fd);
const char *modulename(void);
const char *moduledesc(void);
const char *modulehelp(void);
```

### `init`

Called once at load time. Returns a module-private context pointer (passed back to `process` as `ctx`).

- `in_fd` / `out_fd` — logical file descriptors for input and output data flow.
- `chain_api` — pointer to the `ModuleChain` vtable (see below).
- `config` — configuration string (module-defined format, commonly `key:val key:val` or space-separated tokens).

Return `NULL` on failure.

### `process`

Called when data is available on `trigger_fd`.

- `dir` — direction hint (0 = forward, 1 = reverse, may be ignored).
- `trigger_fd` — the fd that has data ready.
- Return `0` on success, negative on error.

### `modulename`, `moduledesc`, `modulehelp`

All three are **required**.

- `modulename` — short identifier (e.g. `"copy"`).
- `moduledesc` — one-line description.
- `modulehelp` — multi-line help text.

## `ModuleChain` vtable

```c
typedef struct {
    void *ctx;
    int   (*request_outputs)(void *chain_ctx, int count);
    int   (*get_output_fd)(void *chain_ctx, int idx);
    int   (*get_node_id)(void *chain_ctx);
    void *(*get_packet)(void *chain_ctx, int idx, int *out_size);
    int   (*write_packet)(void *chain_ctx, int fd,
                          const uint8_t *data, size_t len);
} ModuleChain;
```

### `get_packet(chain_ctx, idx, out_size)`

Returns a pointer to the next available packet and writes its size into `*out_size`.
Returns `NULL` if no packet is available.

**Ownership**: the returned pointer is owned by the module. The module must either:

- pass it to `write_packet` (transferring ownership), or
- `free()` it after use.

### `write_packet(chain_ctx, fd, data, len)`

Writes `len` bytes from `data` to output `fd`.

**Ownership of `data` is transferred to the framework** — the module must **not** call `free(data)` after `write_packet` returns. The framework will free the buffer when it is no longer needed.

If the module must keep its own copy, it should `malloc`+`memcpy` before calling `write_packet`.

## Ownership Model — Move vs Copy

| Mode | Module does | Framework does |
|---|---|---|
| **Move** (default) | `write_packet(ctx, fd, pkt, sz)` | frees `pkt` when done |
| **Copy** | `cp = malloc(sz); memcpy(cp, pkt, sz); write_packet(ctx, fd, cp, sz); free(pkt);` | frees `cp` when done |

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
void *init(int in_fd, int out_fd, ModuleChain *chain_api, const char *config) {
    struct copy_ctx *ctx = malloc(sizeof(*ctx));
    ctx->in_fd = in_fd;
    ctx->out_fd = out_fd;
    ctx->chain_api = chain_api;
    // parse config ...
    return ctx;
}

int process(void *ctx_ptr, int dir, int trigger_fd) {
    struct copy_ctx *ctx = ctx_ptr;
    int sz;
    uint8_t *pkt = ctx->chain_api->get_packet(ctx->chain_api->ctx, 0, &sz);
    if (!pkt || sz <= 0) return -1;

    int write_fd = (trigger_fd == ctx->in_fd) ? ctx->out_fd : ctx->in_fd;

    if (ctx->mode_copy) {
        uint8_t *cp = malloc(sz);
        memcpy(cp, pkt, sz);
        free(pkt);
        return ctx->chain_api->write_packet(ctx->chain_api->ctx, write_fd, cp, sz);
    } else {
        return ctx->chain_api->write_packet(ctx->chain_api->ctx, write_fd, pkt, sz);
    }
}
```
