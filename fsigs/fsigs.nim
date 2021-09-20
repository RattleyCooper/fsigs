

type 
  FileSignature* = tuple[
    name: string,
    temp: seq[
      tuple[offset: int, signature: string]
    ]
  ]

proc fileSignature*(name: string, signature: string, offset: int = 0): FileSignature =
  ## Create new file signatures.
  #
  result = (
    name,
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

  # Preinstantiate sequence of chars and read slice of bytes into it.
  var chars = newString(sliceEnd)
  discard f.readChars(chars, sliceStart, sliceEnd)
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
