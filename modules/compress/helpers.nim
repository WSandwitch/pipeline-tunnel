
type
  ModuleChain* = object
    ctx*: pointer
    request_outputs*: proc(ctx: pointer, count: cint): cint {.cdecl.}
    get_output_fd*: proc(ctx: pointer, idx: cint): cint {.cdecl.}
    get_node_id*: proc(ctx: pointer): cint {.cdecl.}
    write_packet*: proc(ctx: pointer, output_id: cint, data: pointer, len: csize_t): cint {.cdecl.}
    request_heartbeat*: proc(ctx: pointer, interval_sec: cint): cint {.cdecl.}
    set_src*: proc(ctx: pointer, src_idx: cint) {.cdecl.}

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
    Rle, Zstd, Snappy, Gzip, Lz4, Brotli, Lzo, Lzma

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
    lz4CompressDefault*: proc(src: pointer, dst: pointer, srcSize: cint, dstCapacity: cint): cint {.cdecl.}
    lz4DecompressSafe*: proc(src: pointer, dst: pointer, compressedSize: cint, dstCapacity: cint): cint {.cdecl.}
    lz4CompressBound*: proc(inputSize: cint): cint {.cdecl.}
    brotliEncoderCompress*: proc(quality: cint, lgwin: cint, mode: cint, inputSize: csize_t, inputBuffer: pointer, encodedSize: ptr csize_t, encodedBuffer: pointer): cint {.cdecl.}
    brotliDecoderDecompress*: proc(encodedSize: csize_t, encodedBuffer: pointer, decodedSize: ptr csize_t, decodedBuffer: pointer): cint {.cdecl.}
    brotliEncoderMaxCompressedSize*: proc(inputSize: csize_t): csize_t {.cdecl.}
    lzo1x1Compress*: proc(src: pointer, srcLen: csize_t, dst: pointer, dstLen: ptr csize_t, wrkmem: pointer): cint {.cdecl.}
    lzo1xDecompress*: proc(src: pointer, srcLen: csize_t, dst: pointer, dstLen: ptr csize_t, wrkmem: pointer): cint {.cdecl.}
    lzoInitV2*: proc(v: cuint, s1: cint, s2: cint, s3: cint, s4: cint, s5: cint, s6: cint, s7: cint, s8: cint, s9: cint): cint {.cdecl.}
    lzoWrkmem*: pointer
    lzmaEasyBufferEncode*: proc(level: cuint, check: cuint, allocator: pointer, src: pointer, srcLen: csize_t, dst: pointer, dstPos: ptr csize_t, dstSize: csize_t): cint {.cdecl.}
    lzmaStreamBufferDecode*: proc(memlimit: ptr uint64, flags: cuint, allocator: pointer, src: pointer, srcPos: ptr csize_t, srcSize: csize_t, dst: pointer, dstPos: ptr csize_t, dstSize: csize_t): cint {.cdecl.}

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

proc loadLz4*(ctx: ptr CompressCtx): cint =
  let h = dlopen("liblz4.so.1", RTLD_NOW)
  if h == nil:
    return -1
  ctx.dl_handle = h
  ctx.lz4CompressDefault = cast[typeof(ctx.lz4CompressDefault)](dlsym(h, "LZ4_compress_default"))
  ctx.lz4DecompressSafe = cast[typeof(ctx.lz4DecompressSafe)](dlsym(h, "LZ4_decompress_safe"))
  ctx.lz4CompressBound = cast[typeof(ctx.lz4CompressBound)](dlsym(h, "LZ4_compressBound"))
  if ctx.lz4CompressDefault == nil or ctx.lz4DecompressSafe == nil:
    discard dlclose(h)
    ctx.dl_handle = nil
    return -1
  return 0

proc loadBrotli*(ctx: ptr CompressCtx): cint =
  let hEnc = dlopen("libbrotlienc.so.1", RTLD_NOW)
  if hEnc == nil:
    return -1
  let hDec = dlopen("libbrotlidec.so.1", RTLD_NOW)
  if hDec == nil:
    discard dlclose(hEnc)
    return -1
  ctx.dl_handle = hEnc
  ctx.brotliEncoderCompress = cast[typeof(ctx.brotliEncoderCompress)](dlsym(hEnc, "BrotliEncoderCompress"))
  ctx.brotliEncoderMaxCompressedSize = cast[typeof(ctx.brotliEncoderMaxCompressedSize)](dlsym(hEnc, "BrotliEncoderMaxCompressedSize"))
  ctx.brotliDecoderDecompress = cast[typeof(ctx.brotliDecoderDecompress)](dlsym(hDec, "BrotliDecoderDecompress"))
  if ctx.brotliEncoderCompress == nil or ctx.brotliDecoderDecompress == nil:
    discard dlclose(hDec)
    discard dlclose(hEnc)
    ctx.dl_handle = nil
    return -1
  return 0

proc loadLzo*(ctx: ptr CompressCtx): cint =
  let h = dlopen("liblzo2.so.2", RTLD_NOW)
  if h == nil:
    return -1
  ctx.dl_handle = h
  ctx.lzo1x1Compress = cast[typeof(ctx.lzo1x1Compress)](dlsym(h, "lzo1x_1_compress"))
  ctx.lzo1xDecompress = cast[typeof(ctx.lzo1xDecompress)](dlsym(h, "lzo1x_decompress"))
  ctx.lzoInitV2 = cast[typeof(ctx.lzoInitV2)](dlsym(h, "__lzo_init_v2"))
  if ctx.lzo1x1Compress == nil or ctx.lzo1xDecompress == nil:
    discard dlclose(h)
    ctx.dl_handle = nil
    return -1
  if ctx.lzoInitV2 != nil:
    discard ctx.lzoInitV2(1, -1, -1, -1, -1, -1, -1, -1, -1, -1)
  return 0

proc loadLzma*(ctx: ptr CompressCtx): cint =
  let h = dlopen("liblzma.so.5", RTLD_NOW)
  if h == nil:
    return -1
  ctx.dl_handle = h
  ctx.lzmaEasyBufferEncode = cast[typeof(ctx.lzmaEasyBufferEncode)](dlsym(h, "lzma_easy_buffer_encode"))
  ctx.lzmaStreamBufferDecode = cast[typeof(ctx.lzmaStreamBufferDecode)](dlsym(h, "lzma_stream_buffer_decode"))
  if ctx.lzmaEasyBufferEncode == nil or ctx.lzmaStreamBufferDecode == nil:
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
  elif strNcmp(algStart, "lz4", 3) == 0 and algLen == 3:
    algo[] = Algo.Lz4
  elif strNcmp(algStart, "brotli", 6) == 0 and algLen == 6:
    algo[] = Algo.Brotli
  elif strNcmp(algStart, "lzo", 3) == 0 and algLen == 3:
    algo[] = Algo.Lzo
  elif strNcmp(algStart, "lzma", 4) == 0 and algLen == 4:
    algo[] = Algo.Lzma
  else:
    algo[] = Algo.Rle
  if c[0] == ':':
    c = cast[cstring](cast[uint](c) + 1)
    level[] = atoi_c(c)
