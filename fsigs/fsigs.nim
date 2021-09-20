
type 
  FileSignatures* = enum
    fSigUnknown,
    fSigShebang,
    fSigPcapLe,
    fSigPcapBe,
    fSigNsPcapLe,
    fSigNsPcapBe,
    fSigPcapNextGeneration,
    fSigRpm,
    fSigSqLite3,
    fSigKindleBin,
    fSigIco,
    fSigBac,
    fSigIdx,
    fSigBz2,
    fSigGif87a,
    fSigGif89a,
    fSigTif,
    fSigTiff,
    fSigCr2,
    fSigCin,
    fSigZip,
    fSigZipEmpty,
    fSigZipSpanned,
    fSigExe,
    fSigExeMz,
    fSigLzip,
    fSigRar1p5,
    fSigRar5p0,
    fSigRar0,
    fSigRar1,
    fSigElf,
    fSigPng,
    fSigCom,
    fSigClass,
    fSigMachO32,
    fSigMachO64,
    fSigMachOR32,
    fSigMachOR64,
    fSigJks,
    fSigPdf,
    fSigOgg,
    fSigPsd,
    fSigMp3v0,
    fSigMp3v1,
    fSigMp3v2,
    fSigMp3v3,
    fSigBmp,
    fSigDib,
    fSigIso,
    fSigFits,
    fSigFlac,
    fSigMidi,
    fSigMid,
    fSigDoc,
    fSigXls,
    fSigPpt,
    fSigMsg,
    fSigDex,
    fSigVmdk,
    fSigCrx,
    fSigWebP,
    fSigFh8,
    fSigDmg,
    fSigCwk5v0,
    fSigCwk5v1,
    fSigCwk5v2,
    fSigCwk6v0,
    fSigCwk6v1,
    fSigCwk6v2,
    fSigToast0,
    fSigToast1,
    fSig3gp,
    fSig3gp2,
    fSigOar,
    fSigTox,
    fSigMlv,
    fSigUbdc0,
    fSigUbdc1,
    fSigLz4,
    fSigCab,
    fSigFlif,
    fSigStg,
    fSigDjvu,
    fSigDjv,
    fSigXml0,
    fSigXml1,
    fSigXml2,
    fSigXml3,
    fSigXml4,
    fSigXml5,
    fSigWoff,
    fSigWoff2,
    fSigDer,
    fSigDcm,
    fSigLep,
    fSigUBoot,
    fSigDat,
    fSigNes,
    fSig7z,
    fSigTarGz,
    fSigTarXz,
    fSigTarZLzw,
    fSigTarZLzh,
    fSigTar0,
    fSigTar1,
    fSigMkv,
    fSigMka,
    fSigMks,
    fSigMk3d,
    fSigWebm,
    fSigWasm,
    fSigSwfCws,
    fSigSwfFws,
    fSigDeb,
    fSigRtf,
    fSigMpegP,
    fSigMpgP,
    fSigVob,
    fSigM2p,
    fSigMpeg,
    fSigMpg,
    fSigMp4,
    fSigZlib0,
    fSigZlib1,
    fSigZlib2,
    fSigZlib3,
    fSigZlib4,
    fSigZlib5,
    fSigZlib6,
    fSigZlib7,
    fSigLzfse,
    fSigOrc,
    fSigAvro,
    fSigRc,
    fSigLuac,
    fSigPyc,
    fSigAlias,
    fSigEml,
    fSigPgp,
    fSigVpk,
    fSigAff,
    fSigJpg0,
    fSigJpg1,
    fSigJpg2,
    fSigJpg3,
    fSigJpeg0,
    fSigJpeg1,
    fSigJpeg2,
    fSigJpeg3,
    fSigXcf,
    fSigFlv,
    fSigDatWinReg,
    fSigTxtUtf8,
    fSigTxtUtf16Le,
    fSigTxtUtf16Be,
    fSigTxtUtf32Le,
    fSigTxtUtf32Be,
    fSigTxtScsu,
    fSigTxtUtf7,
    fSigUtfEbcdic,
    fSigPostScript,
    fSigChm,
    fSigSdi,
    fSigTape,
    fSigWav,
    fSigAvi,
    fSigIlbm,
    fSigLbm,
    fSigIbm,
    fSigIff,
    fSig8svx,
    fSig8sv,
    fSigSvx,
    fSigSnd,
    fSig8svIff,
    fSigAsf,
    fSigWma,
    fSigWmv

  FileSignature* = tuple[
    id: FileSignatures,
    temp: seq[
      tuple[offset: int, signature: string]
    ]
  ]

proc `$`*(fs: FileSignature): string =
  $fs.id

proc fileSignature*(id: FileSignatures, signature: string, offset: int = 0): FileSignature =
  ## Create new file signatures.
  #

  result = (
    id,
    @[(offset, signature)]
  )

proc matches*(s: string, fs: FileSignature): bool = 
  ## Check if a filesignature matches a string.
  #

  result = true
  for (offset, sig) in fs.temp:
    let sigLen = sig.len
    if (sigLen + offset) > s.len:  # Signature exceeds size of file.
      result = false
      break

    let sigHigh = (sigLen - 1) + offset
    if sig != s[offset..sigHigh]:  # Signature doesn't match
      result = false
      break

proc matches*(f: File, fs: FileSignature): bool =
  ## Check if the given file matches the file signature.
  #

  f.setFilePos(0)

  # Get the slice indices of bytes we'll use for comparison.
  var sliceStart = fs.temp[0].offset
  var sliceEnd = fs.temp[^1].offset + (fs.temp[^1].signature.len)

  # Preinstantiate string and read slice of bytes into it.
  var chars = newString(sliceEnd+sliceStart)
  discard f.readChars(chars, sliceStart, sliceEnd)

  # Negate the starting slice 
  chars = chars[sliceStart..^1]
  chars.matches(fs)

proc `==`*(f: File, fs: FileSignature): bool =
  ## check if file matches file signature
  #

  f.matches(fs)

proc fileMatches*(filePath: string, fs: FileSignature): bool =
  ## Load file from given filepath and check if it matches the given
  ## file signature.
  #

  var f: File
  if not f.open(filePath, fmRead):
    raise newException(OSError, "File does not exist.  Cannot continue.")
  
  result = f.matches(fs)
  f.close()

proc matchesAny*(f: File, sigs: seq[FileSignature]): bool =
  ## Check if file matches any of the given file signatures.
  #
  
  result = false
  for sig in sigs:
    if f.matches(sig): 
      result = true
      break

proc `==`*(fss: FileSignatures, fs: FileSignature): bool =
  fss == fs.id

proc `==`*(fs: FileSignature, fss: FileSignatures): bool =
  fs.id == fss

proc signature*(f: File, sigs: seq[FileSignature]): FileSignatures =
  ## Get the id of the matching file signature.
  #
  
  result = fSigUnknown
  for sig in sigs:
    if f.matches(sig): 
      result = sig.id
      break
