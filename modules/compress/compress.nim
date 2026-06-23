

type
  ModuleChain = object
    ctx: pointer
    request_outputs: proc(ctx: pointer, count: cint): cint {.cdecl.}
    get_output_fd: proc(ctx: pointer, idx: cint): cint {.cdecl.}
    get_node_id: proc(ctx: pointer): cint {.cdecl.}
    get_packet: proc(ctx: pointer, idx: cint, out_size: ptr cint): pointer {.cdecl.}
    write_packet: proc(ctx: pointer, output_id: cint, data: pointer, len: csize_t): cint {.cdecl.}
    request_heartbeat: proc(ctx: pointer, interval_sec: cint): cint {.cdecl.}

const
  RTLD_NOW = 2
  RTLD_DEFAULT = 0'i64

proc dlopen(path: cstring, mode: cint): pointer {.importc, cdecl.}
proc dlsym(handle: pointer, symbol: cstring): pointer {.importc, cdecl.}
proc dlclose(handle: pointer): cint {.importc, cdecl.}
proc dlerror(): cstring {.importc, cdecl.}

proc c_malloc(size: csize_t): pointer {.importc: "malloc", cdecl.}
proc c_free(p: pointer) {.importc: "free", cdecl.}
proc c_realloc(p: pointer, size: csize_t): pointer {.importc: "realloc", cdecl.}

proc fprintf(stream: pointer, fmt: cstring): cint {.importc, cdecl, varargs, discardable.}
var stderr {.importc.}: pointer

proc strNcmp(a: cstring, b: cstring, n: csize_t): cint =
  var i: csize_t = 0
  while i < n:
    if a[i] != b[i]:
      return (if a[i] > b[i]: 1 else: -1)
    if a[i] == '\0':
      return 0
    i += 1
  return 0

proc strStr(haystack: cstring, needle: cstring): cstring =
  var h = haystack
  while h[0] != '\0':
    var i: csize_t = 0
    while needle[i] != '\0' and h[i] == needle[i]:
      i += 1
    if needle[i] == '\0':
      return h
    h = cast[cstring](cast[uint](h) + 1)
  return nil

proc atoi_c(s: cstring): cint {.importc: "atoi", cdecl.}

type
  Algo {.pure.} = enum
    Rle, Zstd, Snappy, Gzip

  CompressCtx = object
    api: ptr ModuleChain
    algo: Algo
    level: cint
    trace: bool
    node_id: cint
    dl_handle: pointer
    zstdIsError: proc(code: csize_t): cuint {.cdecl.}
    zstdCompressBound: proc(srcSize: csize_t): csize_t {.cdecl.}
    zstdGetFrameContentSize: proc(src: pointer, srcSize: csize_t): uint64 {.cdecl.}
    zstdCompress: proc(dst: pointer, dstCapacity: csize_t, src: pointer, srcSize: csize_t, level: cint): csize_t {.cdecl.}
    zstdDecompress: proc(dst: pointer, dstCapacity: csize_t, src: pointer, srcSize: csize_t): csize_t {.cdecl.}
    snappyCompress: proc(input: pointer, inputLen: csize_t, compressed: pointer, compressedLen: ptr csize_t): cint {.cdecl.}
    snappyUncompress: proc(compressed: pointer, compressedLen: csize_t, uncompressed: pointer, uncompressedLen: ptr csize_t): cint {.cdecl.}
    snappyMaxCompressedLength: proc(sourceLen: csize_t): csize_t {.cdecl.}
    snappyUncompressedLength: proc(compressed: pointer, compressedLen: csize_t, res: ptr csize_t): cint {.cdecl.}
    deflateInit2: proc(strm: pointer, level: cint, mth: cint, windowBits: cint, memLevel: cint, strategy: cint, zv: cstring, streamSize: cint): cint {.cdecl.}
    deflate: proc(strm: pointer, flush: cint): cint {.cdecl.}
    deflateEnd: proc(strm: pointer): cint {.cdecl.}
    deflateBound: proc(strm: pointer, sourceLen: culong): culong {.cdecl.}
    inflateInit2: proc(strm: pointer, windowBits: cint, zv: cstring, streamSize: cint): cint {.cdecl.}
    inflate: proc(strm: pointer, flush: cint): cint {.cdecl.}
    inflateEnd: proc(strm: pointer): cint {.cdecl.}

  z_stream = object
    next_in: ptr byte
    avail_in: cuint
    total_in: culong
    next_out: ptr byte
    avail_out: cuint
    total_out: culong
    msg: cstring
    state: pointer
    zalloc: pointer
    zfree: pointer
    opaque: pointer
    data_type: cint
    adler: culong
    reserved: culong

const
  Z_OK = 0
  Z_STREAM_END = 1
  Z_FINISH = 4
  Z_BUF_ERROR = -5
  Z_DEFLATED = 8
  Z_DEFAULT_STRATEGY = 0
  ZLIB_VERSION = "1.2.8"

  MAX_PACKET = 131072
  MAX_GZIP_DECOMP = 4 * 1024 * 1024

template traceWrite(ctx: CompressCtx, args: varargs[untyped]) =
  if ctx.trace:
    fprintf(stderr, args)

proc loadZstd(ctx: ptr CompressCtx): cint =
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

proc loadSnappy(ctx: ptr CompressCtx): cint =
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

proc loadGzip(ctx: ptr CompressCtx): cint =
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

proc parseConfig(config: cstring, algo: ptr Algo, level: ptr cint, trace: ptr bool) =
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

proc init(api: ptr ModuleChain, config: cstring): pointer {.exportc, cdecl, dynlib.} =
  if api == nil:
    return nil
  let ctx = cast[ptr CompressCtx](c_malloc(sizeof(CompressCtx).csize_t))
  if ctx == nil:
    return nil
  zeroMem(ctx, sizeof(CompressCtx).csize_t)
  ctx.api = api
  ctx.level = 3
  ctx.dl_handle = nil
  ctx.node_id = api.get_node_id(api.ctx)
  parseConfig(config, addr ctx.algo, addr ctx.level, addr ctx.trace)
  if ctx.algo == Algo.Zstd:
    if loadZstd(ctx) != 0:
      if ctx.trace:
        fprintf(stderr, "[compress node=%d] zstd not available\n", ctx.node_id)
      c_free(ctx)
      return nil
  elif ctx.algo == Algo.Snappy:
    if loadSnappy(ctx) != 0:
      if ctx.trace:
        fprintf(stderr, "[compress node=%d] snappy not available\n", ctx.node_id)
      c_free(ctx)
      return nil
  elif ctx.algo == Algo.Gzip:
    if loadGzip(ctx) != 0:
      if ctx.trace:
        fprintf(stderr, "[compress node=%d] gzip not available\n", ctx.node_id)
      c_free(ctx)
      return nil
  if ctx.trace:
    fprintf(stderr, "[compress node=%d init] %s:%d\n", ctx.node_id,
      cast[cstring](case ctx.algo
        of Algo.Zstd: "zstd"
        of Algo.Snappy: "snappy"
        of Algo.Gzip: "gzip"
        of Algo.Rle: "rle"), ctx.level)
  return ctx

proc rleCompress(src: pointer, srcLen: csize_t, dst: pointer, dstLen: ptr csize_t): cint =
  var s = cast[ptr byte](src)
  var d = cast[ptr byte](dst)
  var i: csize_t = 0
  var o: csize_t = 0
  let maxDst = dstLen[]
  while i < srcLen:
    var runStart = i
    var b = cast[ptr byte](cast[uint](s) + i)[]
    i += 1
    while i < srcLen and cast[ptr byte](cast[uint](s) + i)[] == b and (i - runStart) < 255:
      i += 1
    let runLen = i - runStart
    if runLen >= 3:
      if o + 3 > maxDst:
        return -1
      cast[ptr byte](cast[uint](d) + o)[] = 0
      o += 1
      cast[ptr byte](cast[uint](d) + o)[] = b
      o += 1
      cast[ptr byte](cast[uint](d) + o)[] = runLen.cuint.byte
      o += 1
    else:
      var litStart = runStart
      var litLen: csize_t = 0
      while i < srcLen and litLen < 255:
        let nb = cast[ptr byte](cast[uint](s) + i)[]
        var lookahead: csize_t = 1
        while (i + lookahead) < srcLen and cast[ptr byte](cast[uint](s) + i + lookahead)[] == nb and lookahead < 255:
          lookahead += 1
        if lookahead >= 3:
          break
        i += 1
        litLen += 1
      if litLen == 0:
        litLen = 1
        i = litStart + 1
      if o + 2 + litLen > maxDst:
        return -1
      cast[ptr byte](cast[uint](d) + o)[] = 1
      o += 1
      cast[ptr byte](cast[uint](d) + o)[] = litLen.cuint.byte
      o += 1
      copyMem(cast[pointer](cast[uint](d) + o), cast[pointer](cast[uint](s) + litStart), litLen)
      o += litLen
  if o >= srcLen:
    if srcLen + 1 > maxDst:
      return -1
    cast[ptr byte](dst)[] = 2
    copyMem(cast[pointer](cast[uint](dst) + 1), src, srcLen)
    dstLen[] = srcLen + 1
    return 0
  dstLen[] = o
  return 0

proc rleDecompressSize(src: pointer, srcLen: csize_t): csize_t =
  var s = cast[ptr byte](src)
  var i: csize_t = 0
  var outSize: csize_t = 0
  while i < srcLen:
    let bt = cast[ptr byte](cast[uint](s) + i)[]
    i += 1
    case bt
    of 0:
      if i + 2 > srcLen: return 0
      let cnt = cast[ptr byte](cast[uint](s) + i + 1)[]  # skip value byte
      i += 2
      outSize += cnt.csize_t
    of 1:
      if i >= srcLen: return 0
      let litLen = cast[ptr byte](cast[uint](s) + i)[]
      i += 1
      if i + litLen.csize_t > srcLen: return 0
      i += litLen.csize_t
      outSize += litLen.csize_t
    of 2:
      outSize = srcLen - 1
      return outSize
    else:
      return 0
  return outSize

proc rleDecompress(src: pointer, srcLen: csize_t, dst: pointer, dstLen: ptr csize_t): cint =
  if srcLen >= 1 and cast[ptr byte](src)[] == 2:
    let copyLen = srcLen - 1
    if copyLen > dstLen[]:
      return -1
    copyMem(dst, cast[pointer](cast[uint](src) + 1), copyLen)
    dstLen[] = copyLen
    return 0
  var s = cast[ptr byte](src)
  var d = cast[ptr byte](dst)
  var i: csize_t = 0
  var o: csize_t = 0
  while i < srcLen:
    let bt = cast[ptr byte](cast[uint](s) + i)[]
    i += 1
    case bt
    of 0:
      if i + 2 > srcLen: return -1
      let b = cast[ptr byte](cast[uint](s) + i)[]
      let cnt = cast[ptr byte](cast[uint](s) + i + 1)[]
      i += 2
      if o + cnt.csize_t > dstLen[]: return -1
      var fillByte = b
      var fillPtr = cast[pointer](cast[uint](d) + o)
      var fillSize = cnt.csize_t
      cast[ptr byte](fillPtr)[] = fillByte
      var filled: csize_t = 1
      while filled < fillSize:
        let chunk = min(filled, fillSize - filled)
        copyMem(cast[pointer](cast[uint](fillPtr) + filled), fillPtr, chunk)
        filled += chunk
      o += cnt.csize_t
    of 1:
      if i >= srcLen: return -1
      let litLen = cast[ptr byte](cast[uint](s) + i)[]
      i += 1
      if i + litLen.csize_t > srcLen or o + litLen.csize_t > dstLen[]: return -1
      copyMem(cast[pointer](cast[uint](d) + o), cast[pointer](cast[uint](s) + i), litLen.csize_t)
      i += litLen.csize_t
      o += litLen.csize_t
    of 2:
      let copyLen = srcLen - 1
      if copyLen > dstLen[]: return -1
      copyMem(dst, cast[pointer](cast[uint](src) + 1), copyLen)
      dstLen[] = copyLen
      return 0
    else:
      return -1
  dstLen[] = o
  return 0

proc process(ctxPtr: pointer, dir: cint, triggerIdx: cint): cint {.exportc, cdecl, dynlib.} =
  if ctxPtr == nil: return -1
  let ctx = cast[ptr CompressCtx](ctxPtr)
  if dir < 0 or dir > 1: return 0
  var sz: cint = 0
  let pkt = ctx.api.get_packet(ctx.api.ctx, 0, addr sz)
  if pkt == nil or sz <= 0: return -1
  let srcLen = sz.csize_t
  let writeDst: cint = if triggerIdx == 0: 1 else: 0
  var outLen: csize_t = 0
  var outBuf: pointer = nil
  if triggerIdx == 0:
    var maxOut: csize_t = 0
    case ctx.algo
    of Algo.Zstd:
      maxOut = ctx.zstdCompressBound(srcLen)
      outBuf = c_malloc(maxOut)
      if outBuf == nil: return -1
      let ret = ctx.zstdCompress(outBuf, maxOut, pkt, srcLen, ctx.level)
      if ctx.zstdIsError(ret) != 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] zstd compress failed\n", ctx.node_id)
        return -1
      outLen = ret
    of Algo.Snappy:
      maxOut = ctx.snappyMaxCompressedLength(srcLen)
      outBuf = c_malloc(maxOut)
      if outBuf == nil: return -1
      var compressedLen: csize_t = maxOut
      if ctx.snappyCompress(pkt, srcLen, outBuf, addr compressedLen) != 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] snappy compress failed\n", ctx.node_id)
        return -1
      outLen = compressedLen
    of Algo.Gzip:
      var strm: z_stream
      zeroMem(addr strm, sizeof(z_stream).csize_t)
      if ctx.deflateInit2(addr strm, ctx.level, Z_DEFLATED, 15 or 16, 8, Z_DEFAULT_STRATEGY, ZLIB_VERSION, sizeof(z_stream).cint) != Z_OK:
        traceWrite(ctx[], "[compress node=%d] gzip deflateInit2 failed\n", ctx.node_id)
        return -1
      maxOut = ctx.deflateBound(addr strm, srcLen.culong).csize_t
      outBuf = c_malloc(maxOut)
      if outBuf == nil:
        discard ctx.deflateEnd(addr strm)
        return -1
      strm.next_in = cast[ptr byte](pkt)
      strm.avail_in = srcLen.cuint
      strm.next_out = cast[ptr byte](outBuf)
      strm.avail_out = maxOut.cuint
      let ret = ctx.deflate(addr strm, Z_FINISH)
      outLen = strm.total_out.csize_t
      discard ctx.deflateEnd(addr strm)
      if ret != Z_STREAM_END:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] gzip deflate failed ret=%d\n", ctx.node_id, ret)
        return -1
    of Algo.Rle:
      maxOut = srcLen * 2 + 64
      outBuf = c_malloc(maxOut)
      if outBuf == nil: return -1
      var rleLen = maxOut
      if rleCompress(pkt, srcLen, outBuf, addr rleLen) != 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] rle compress failed\n", ctx.node_id)
        return -1
      outLen = rleLen
  else:
    case ctx.algo
    of Algo.Zstd:
      let contentSize = ctx.zstdGetFrameContentSize(pkt, srcLen)
      var cap: csize_t
      if contentSize == 0xFFFF_FFFF_FFFF_FFFF'u64 or contentSize == 0xFFFF_FFFF_FFFF_FFFE'u64:
        cap = srcLen * 3 + 65536
      else:
        cap = contentSize.csize_t
      outBuf = c_malloc(cap)
      if outBuf == nil: return -1
      let ret = ctx.zstdDecompress(outBuf, cap, pkt, srcLen)
      if ctx.zstdIsError(ret) != 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] zstd decompress failed\n", ctx.node_id)
        return -1
      outLen = ret
    of Algo.Snappy:
      var uncompLen: csize_t = 0
      if ctx.snappyUncompressedLength(pkt, srcLen, addr uncompLen) != 0:
        traceWrite(ctx[], "[compress node=%d] snappy uncompressed length failed\n", ctx.node_id)
        return -1
      outBuf = c_malloc(uncompLen)
      if outBuf == nil: return -1
      outLen = uncompLen
      if ctx.snappyUncompress(pkt, srcLen, outBuf, addr outLen) != 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] snappy uncompress failed\n", ctx.node_id)
        return -1
    of Algo.Gzip:
      var cap = (srcLen * 3 div 2 + 65536).csize_t
      outBuf = c_malloc(cap)
      if outBuf == nil: return -1
      var strm: z_stream
      zeroMem(addr strm, sizeof(z_stream).csize_t)
      if ctx.inflateInit2(addr strm, 15 or 16, ZLIB_VERSION, sizeof(z_stream).cint) != Z_OK:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] gzip inflateInit2 failed\n", ctx.node_id)
        return -1
      strm.next_in = cast[ptr byte](pkt)
      strm.avail_in = srcLen.cuint
      strm.next_out = cast[ptr byte](outBuf)
      strm.avail_out = cap.cuint
      var ret: cint
      while true:
        ret = ctx.inflate(addr strm, Z_FINISH)
        if ret == Z_STREAM_END:
          break
        if ret == Z_BUF_ERROR and strm.avail_out == 0:
          let written = strm.total_out
          if written.csize_t >= MAX_GZIP_DECOMP:
            discard ctx.inflateEnd(addr strm)
            c_free(outBuf)
            return -1
          let newCap = cap * 2
          let newBuf = c_realloc(outBuf, newCap)
          if newBuf == nil:
            discard ctx.inflateEnd(addr strm)
            c_free(outBuf)
            return -1
          outBuf = newBuf
          cap = newCap
          strm.next_out = cast[ptr byte](cast[uint](outBuf) + written)
          strm.avail_out = (cap - written.csize_t).cuint
        elif ret != Z_OK and ret != Z_BUF_ERROR:
          discard ctx.inflateEnd(addr strm)
          c_free(outBuf)
          traceWrite(ctx[], "[compress node=%d] gzip inflate failed ret=%d\n", ctx.node_id, ret)
          return -1
        else:
          discard ctx.inflateEnd(addr strm)
          c_free(outBuf)
          return -1
      outLen = strm.total_out.csize_t
      discard ctx.inflateEnd(addr strm)
    of Algo.Rle:
      let decompSize = rleDecompressSize(pkt, srcLen)
      if decompSize == 0:
        traceWrite(ctx[], "[compress node=%d] rle decompress size failed\n", ctx.node_id)
        return -1
      outBuf = c_malloc(decompSize)
      if outBuf == nil: return -1
      var rleLen = decompSize
      if rleDecompress(pkt, srcLen, outBuf, addr rleLen) != 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] rle decompress failed\n", ctx.node_id)
        return -1
      outLen = rleLen
  if outLen == 0 or outLen > 0x7FFFFFFF:
    if outBuf != nil: c_free(outBuf)
    traceWrite(ctx[], "[compress node=%d] bad output len=%zu\n", ctx.node_id, outLen)
    return -1
  if ctx.trace:
    let ratio = if outLen > 0: cast[float64](srcLen) / cast[float64](outLen) else: 0.0
    fprintf(stderr, "[compress node=%d %s] %s sz=%d -> %d (%.1fx)\n",
      ctx.node_id, if triggerIdx == 0: "fw" else: "rv",
      cast[cstring](case ctx.algo
        of Algo.Zstd: "zstd"
        of Algo.Snappy: "snappy"
        of Algo.Gzip: "gzip"
        of Algo.Rle: "rle"),
      srcLen.cint, outLen.cint, ratio)
  let wr = ctx.api.write_packet(ctx.api.ctx, writeDst, outBuf, outLen)
  return wr

proc modulename(): cstring {.exportc, cdecl, dynlib.} =
  return "compress"

proc moduleversion(): cstring {.exportc, cdecl, dynlib.} =
  return "1.0.0"

proc moduledesc(): cstring {.exportc, cdecl, dynlib.} =
  return "Compression module (rle/zstd/snappy/gzip)"

proc modulehelp(): cstring {.exportc, cdecl, dynlib.} =
  return "Compresses ext->wire, decompresses wire->ext.\n" &
         "Config: algorithm[:level][,trace]\n" &
         "  rle (default, built-in), zstd:N, snappy, gzip:N\n" &
         "Example: \"zstd:3\" or \"snappy\" or \"\" (default=rle)"
