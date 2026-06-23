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
  elif ctx.algo == Algo.Lz4:
    if loadLz4(ctx) != 0:
      if ctx.trace:
        fprintf(stderr, "[compress node=%d] lz4 not available\n", ctx.node_id)
      c_free(ctx)
      return nil
  elif ctx.algo == Algo.Brotli:
    if loadBrotli(ctx) != 0:
      if ctx.trace:
        fprintf(stderr, "[compress node=%d] brotli not available\n", ctx.node_id)
      c_free(ctx)
      return nil
  elif ctx.algo == Algo.Lzo:
    if loadLzo(ctx) != 0:
      if ctx.trace:
        fprintf(stderr, "[compress node=%d] lzo not available\n", ctx.node_id)
      c_free(ctx)
      return nil
    ctx.lzoWrkmem = c_malloc(65536)
    if ctx.lzoWrkmem == nil:
      c_free(ctx)
      return nil
  elif ctx.algo == Algo.Lzma:
    if loadLzma(ctx) != 0:
      if ctx.trace:
        fprintf(stderr, "[compress node=%d] lzma not available\n", ctx.node_id)
      c_free(ctx)
      return nil
  if ctx.trace:
    fprintf(stderr, "[compress node=%d init] %s:%d\n", ctx.node_id,
      cast[cstring](case ctx.algo
        of Algo.Zstd: "zstd"
        of Algo.Snappy: "snappy"
        of Algo.Gzip: "gzip"
        of Algo.Rle: "rle"
        of Algo.Lz4: "lz4"
        of Algo.Brotli: "brotli"
        of Algo.Lzo: "lzo"
        of Algo.Lzma: "lzma"), ctx.level)
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
    of Algo.Lz4:
      maxOut = ctx.lz4CompressBound(srcLen.cint).csize_t
      outBuf = c_malloc(maxOut)
      if outBuf == nil: return -1
      let lz4Ret = ctx.lz4CompressDefault(pkt, outBuf, srcLen.cint, maxOut.cint)
      if lz4Ret <= 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] lz4 compress failed ret=%d\n", ctx.node_id, lz4Ret)
        return -1
      outLen = lz4Ret.csize_t
    of Algo.Brotli:
      maxOut = ctx.brotliEncoderMaxCompressedSize(srcLen)
      outBuf = c_malloc(maxOut)
      if outBuf == nil: return -1
      var encLen = maxOut
      if ctx.brotliEncoderCompress(ctx.level, 22, 0, srcLen, pkt, addr encLen, outBuf) == 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] brotli compress failed\n", ctx.node_id)
        return -1
      outLen = encLen
    of Algo.Lzo:
      maxOut = srcLen + srcLen div 16 + 64 + 3
      outBuf = c_malloc(maxOut)
      if outBuf == nil: return -1
      var lzoLen = maxOut
      if ctx.lzo1x1Compress(pkt, srcLen, outBuf, addr lzoLen, ctx.lzoWrkmem) != 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] lzo compress failed\n", ctx.node_id)
        return -1
      outLen = lzoLen
    of Algo.Lzma:
      maxOut = srcLen + srcLen + 65536
      outBuf = c_malloc(maxOut)
      if outBuf == nil: return -1
      var outPos: csize_t = 0
      let lzmaRet = ctx.lzmaEasyBufferEncode(ctx.level.cuint, 4, nil, pkt, srcLen, outBuf, addr outPos, maxOut)
      if lzmaRet != 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] lzma compress failed ret=%d\n", ctx.node_id, lzmaRet)
        return -1
      outLen = outPos
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
    of Algo.Lz4:
      var cap = srcLen * 3
      outBuf = c_malloc(cap)
      if outBuf == nil: return -1
      let lz4Ret = ctx.lz4DecompressSafe(pkt, outBuf, srcLen.cint, cap.cint)
      if lz4Ret < 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] lz4 decompress failed ret=%d\n", ctx.node_id, lz4Ret)
        return -1
      outLen = lz4Ret.csize_t
    of Algo.Brotli:
      var cap = srcLen * 3 + 65536
      outBuf = c_malloc(cap)
      if outBuf == nil: return -1
      var decLen = cap
      if ctx.brotliDecoderDecompress(srcLen, pkt, addr decLen, outBuf) == 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] brotli decompress failed\n", ctx.node_id)
        return -1
      outLen = decLen
    of Algo.Lzo:
      var cap = srcLen * 3
      outBuf = c_malloc(cap)
      if outBuf == nil: return -1
      var lzoLen = cap
      if ctx.lzo1xDecompress(pkt, srcLen, outBuf, addr lzoLen, nil) != 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] lzo decompress failed\n", ctx.node_id)
        return -1
      outLen = lzoLen
    of Algo.Lzma:
      var cap = srcLen * 3
      outBuf = c_malloc(cap)
      if outBuf == nil: return -1
      var outPos: csize_t = 0
      var srcPos: csize_t = 0
      var memlimit: uint64 = 0xFFFF_FFFF_FFFF_FFFF'u64
      let lzmaRet = ctx.lzmaStreamBufferDecode(addr memlimit, 0, nil, pkt, addr srcPos, srcLen, outBuf, addr outPos, cap)
      if lzmaRet != 0:
        c_free(outBuf)
        traceWrite(ctx[], "[compress node=%d] lzma decompress failed ret=%d\n", ctx.node_id, lzmaRet)
        return -1
      outLen = outPos
  if outLen == 0 or outLen > 0x7FFFFFFF:
    if outBuf != nil: c_free(outBuf)
    traceWrite(ctx[], "[compress node=%d] bad output len=%zu\n", ctx.node_id, outLen)
    return -1
  if ctx.trace:
    let ratio = if outLen > 0: cast[float64](srcLen) / cast[float64](outLen) else: 0.0
    fprintf(stderr, "[compress node=%d %s] %s sz=%d -> %d (%.1fx)\n",
      ctx.node_id, cast[cstring](if triggerIdx == 0: "fw" else: "rv"),
      cast[cstring](case ctx.algo
        of Algo.Zstd: "zstd"
        of Algo.Snappy: "snappy"
        of Algo.Gzip: "gzip"
        of Algo.Rle: "rle"
        of Algo.Lz4: "lz4"
        of Algo.Brotli: "brotli"
        of Algo.Lzo: "lzo"
        of Algo.Lzma: "lzma"),
      srcLen.cint, outLen.cint, ratio)
  let wr = ctx.api.write_packet(ctx.api.ctx, writeDst, outBuf, outLen)
  return wr

proc modulename*(): cstring {.exportc, cdecl, dynlib.} =
  return "compress"

proc moduleversion*(): cstring {.exportc, cdecl, dynlib.} =
  return "1.0.0"

proc moduledesc*(): cstring {.exportc, cdecl, dynlib.} =
  return "Compression module (rle/zstd/snappy/gzip/lz4/brotli/lzo/lzma)"

proc modulehelp*(): cstring {.exportc, cdecl, dynlib.} =
  return "Compresses ext->wire, decompresses wire->ext.\n" &
         "Config: algorithm[:level][,trace]\n" &
         "  rle (default, built-in), zstd:N, snappy, gzip:N,\n" &
         "  lz4, brotli:N, lzo, lzma:N\n" &
         "Example: \"zstd:3\" or \"snappy\" or \"\" (default=rle)"
