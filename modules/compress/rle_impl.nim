proc rleCompress*(src: pointer, srcLen: csize_t, dst: pointer, dstLen: ptr csize_t): cint =
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

proc rleDecompressSize*(src: pointer, srcLen: csize_t): csize_t =
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

proc rleDecompress*(src: pointer, srcLen: csize_t, dst: pointer, dstLen: ptr csize_t): cint =
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
