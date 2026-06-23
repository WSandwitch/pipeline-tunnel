
type
  ModuleChain* = object
    ctx*: pointer
    request_outputs*: proc(ctx: pointer, count: cint): cint {.cdecl.}
    get_output_fd*: proc(ctx: pointer, idx: cint): cint {.cdecl.}
    get_node_id*: proc(ctx: pointer): cint {.cdecl.}
    get_packet*: proc(ctx: pointer, idx: cint, out_size: ptr cint): pointer {.cdecl.}
    write_packet*: proc(ctx: pointer, output_id: cint, data: pointer, len: csize_t): cint {.cdecl.}
    request_heartbeat*: proc(ctx: pointer, interval_sec: cint): cint {.cdecl.}

const
  RTLD_NOW* = 2
  RTLD_DEFAULT* = 0'i64

proc dlopen*(path: cstring, mode: cint): pointer {.importc, cdecl.}
proc dlsym*(handle: pointer, symbol: cstring): pointer {.importc, cdecl.}
proc dlclose*(handle: pointer): cint {.importc, cdecl.}
proc dlerror*(): cstring {.importc, cdecl.}

proc c_malloc*(size: csize_t): pointer {.importc: "malloc", cdecl.}
proc c_free*(p: pointer) {.importc: "free", cdecl.}
proc c_realloc*(p: pointer, size: csize_t): pointer {.importc: "realloc", cdecl.}

proc fprintf*(stream: pointer, fmt: cstring): cint {.importc, cdecl, varargs, discardable.}
var stderr* {.importc.}: pointer

proc strNcmp*(a: cstring, b: cstring, n: csize_t): cint =
  var i: csize_t = 0
  while i < n:
    if a[i] != b[i]:
      return (if a[i] > b[i]: 1 else: -1)
    if a[i] == '\0':
      return 0
    i += 1
  return 0

proc strStr*(haystack: cstring, needle: cstring): cstring =
  var h = haystack
  while h[0] != '\0':
    var i: csize_t = 0
    while needle[i] != '\0' and h[i] == needle[i]:
      i += 1
    if needle[i] == '\0':
      return h
    h = cast[cstring](cast[uint](h) + 1)
  return nil

proc atoi_c*(s: cstring): cint {.importc: "atoi", cdecl.}

type
  Algo* {.pure.} = enum
    Rle, Zstd, Snappy, Gzip

  CompressCtx* = object
    api*: ptr ModuleChain
    algo*: Algo
    level*: cint
    trace*: bool
    node_id*: cint
    dl_handle*: pointer
    zstdIsError*: proc(code: csize_t): cuint {.cdecl.}
    zstdCompressBound*: proc(srcSize: csize_t): csize_t {.cdecl.}
    zstdGetFrameContentSize*: proc(src: pointer, srcSize: csize_t): uint64 {.cdecl.}
    zstdCompress*: proc(dst: pointer, dstCapacity: csize_t, src: pointer, srcSize: csize_t, level: cint): csize_t {.cdecl.}
    zstdDecompress*: proc(dst: pointer, dstCapacity: csize_t, src: pointer, srcSize: csize_t): csize_t {.cdecl.}
    snappyCompress*: proc(input: pointer, inputLen: csize_t, compressed: pointer, compressedLen: ptr csize_t): cint {.cdecl.}
    snappyUncompress*: proc(compressed: pointer, compressedLen: csize_t, uncompressed: pointer, uncompressedLen: ptr csize_t): cint {.cdecl.}
    snappyMaxCompressedLength*: proc(sourceLen: csize_t): csize_t {.cdecl.}
    snappyUncompressedLength*: proc(compressed: pointer, compressedLen: csize_t, res: ptr csize_t): cint {.cdecl.}
    deflateInit2*: proc(strm: pointer, level: cint, mth: cint, windowBits: cint, memLevel: cint, strategy: cint, zv: cstring, streamSize: cint): cint {.cdecl.}
    deflate*: proc(strm: pointer, flush: cint): cint {.cdecl.}
    deflateEnd*: proc(strm: pointer): cint {.cdecl.}
    deflateBound*: proc(strm: pointer, sourceLen: culong): culong {.cdecl.}
    inflateInit2*: proc(strm: pointer, windowBits: cint, zv: cstring, streamSize: cint): cint {.cdecl.}
    inflate*: proc(strm: pointer, flush: cint): cint {.cdecl.}
    inflateEnd*: proc(strm: pointer): cint {.cdecl.}

  z_stream* = object
    next_in*: ptr byte
    avail_in*: cuint
    total_in*: culong
    next_out*: ptr byte
    avail_out*: cuint
    total_out*: culong
    msg*: cstring
    state*: pointer
    zalloc*: pointer
    zfree*: pointer
    opaque*: pointer
    data_type*: cint
    adler*: culong
    reserved*: culong

const
  Z_OK* = 0
  Z_STREAM_END* = 1
  Z_FINISH* = 4
  Z_BUF_ERROR* = -5
  Z_DEFLATED* = 8
  Z_DEFAULT_STRATEGY* = 0
  ZLIB_VERSION* = "1.2.8"

  MAX_PACKET* = 131072
  MAX_GZIP_DECOMP* = 4 * 1024 * 1024

template traceWrite*(ctx: CompressCtx, args: varargs[untyped]) =
  if ctx.trace:
    fprintf(stderr, args)

proc loadZstd*(ctx: ptr CompressCtx): cint =
  let h = dlopen("libzstd.so.1", RTLD_NOW)
  if h == nil:
    return -1
  ctx.dl_handle = h
  ctx.zstdCompress = cast[typeof(ctx.zstdCompress)](dlsym(h, "ZSTD_compress"))
  ctx.zstdDecompress = cast[typeof(ctx.zstdDecompress)](dlsym(h, "ZSTD_decompress"))
  ctx.zstdCompressBound = cast[typeof(ctx.zstdCompressBound)](dlsym(h, "ZSTD_compressBound"))
  ctx.zstdGetFrameContentSize = cast[typeof(ctx.zstdGetFrameContentSize)](dlsym(h, "ZSTD_getFrameContentSize"))
  ctx.zstdIsError = cast[typeof(ctx.zstdIsError)](dlsym(h, "ZSTD_isError"))
  if ctx.zstdCompress == nil or ctx.zstdDecompress == nil:
    discard dlclose(h)
    ctx.dl_handle = nil
    return -1
  return 0

proc loadSnappy*(ctx: ptr CompressCtx): cint =
  let h = dlopen("libsnappy.so.1", RTLD_NOW)
  if h == nil:
    return -1
  ctx.dl_handle = h
  ctx.snappyCompress = cast[typeof(ctx.snappyCompress)](dlsym(h, "snappy_compress"))
  ctx.snappyUncompress = cast[typeof(ctx.snappyUncompress)](dlsym(h, "snappy_uncompress"))
  ctx.snappyMaxCompressedLength = cast[typeof(ctx.snappyMaxCompressedLength)](dlsym(h, "snappy_max_compressed_length"))
  ctx.snappyUncompressedLength = cast[typeof(ctx.snappyUncompressedLength)](dlsym(h, "snappy_uncompressed_length"))
  if ctx.snappyCompress == nil or ctx.snappyUncompress == nil:
    discard dlclose(h)
    ctx.dl_handle = nil
    return -1
  return 0

proc loadGzip*(ctx: ptr CompressCtx): cint =
  let h = dlopen("libz.so.1", RTLD_NOW)
  if h == nil:
    return -1
  ctx.dl_handle = h
  ctx.deflateInit2 = cast[typeof(ctx.deflateInit2)](dlsym(h, "deflateInit2_"))
  ctx.deflate = cast[typeof(ctx.deflate)](dlsym(h, "deflate"))
  ctx.deflateEnd = cast[typeof(ctx.deflateEnd)](dlsym(h, "deflateEnd"))
  ctx.deflateBound = cast[typeof(ctx.deflateBound)](dlsym(h, "deflateBound"))
  ctx.inflateInit2 = cast[typeof(ctx.inflateInit2)](dlsym(h, "inflateInit2_"))
  ctx.inflate = cast[typeof(ctx.inflate)](dlsym(h, "inflate"))
  ctx.inflateEnd = cast[typeof(ctx.inflateEnd)](dlsym(h, "inflateEnd"))
  if ctx.deflateInit2 == nil or ctx.inflateInit2 == nil:
    discard dlclose(h)
    ctx.dl_handle = nil
    return -1
  return 0

proc parseConfig*(config: cstring, algo: ptr Algo, level: ptr cint, trace: ptr bool) =
  if config == nil or config[0] == '\0':
    algo[] = Algo.Rle
    return
  if strStr(config, "trace") != nil:
    trace[] = true
  var c = config
  var algStart = c
  var algLen: csize_t = 0
  while c[0] != '\0' and c[0] != ':' and c[0] != ',':
    c = cast[cstring](cast[uint](c) + 1)
    algLen += 1
  if strNcmp(algStart, "rle", 3) == 0 and algLen == 3:
    algo[] = Algo.Rle
  elif strNcmp(algStart, "zstd", 4) == 0 and algLen == 4:
    algo[] = Algo.Zstd
  elif strNcmp(algStart, "snappy", 6) == 0 and algLen == 6:
    algo[] = Algo.Snappy
  elif strNcmp(algStart, "gzip", 4) == 0 and algLen == 4:
    algo[] = Algo.Gzip
  else:
    algo[] = Algo.Rle
  if c[0] == ':':
    c = cast[cstring](cast[uint](c) + 1)
    level[] = atoi_c(c)
