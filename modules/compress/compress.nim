import helpers, rle_impl

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

proc modulename*(): cstring {.exportc, cdecl, dynlib.} =
  return "compress"

proc moduleversion*(): cstring {.exportc, cdecl, dynlib.} =
  return "1.0.0"

proc moduledesc*(): cstring {.exportc, cdecl, dynlib.} =
  return "Compression module (rle/zstd/snappy/gzip)"

proc modulehelp*(): cstring {.exportc, cdecl, dynlib.} =
  return "Compresses ext->wire, decompresses wire->ext.\n" &
         "Config: algorithm[:level][,trace]\n" &
         "  rle (default, built-in), zstd:N, snappy, gzip:N\n" &
         "Example: \"zstd:3\" or \"snappy\" or \"\" (default=rle)"
