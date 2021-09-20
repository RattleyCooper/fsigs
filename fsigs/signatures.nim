

proc fileSignature(name: string, signature: string, offset: int = 0): tuple[name: string, temp: seq[tuple[offset: int, signature: string]]] =
  result = (
    name,
    @[(offset, signature)]
  )

const
  # Shebang at beginning of file.
  SigShebang* = fileSignature("shebang", "\x23\x21")

  # Pcap files (pcap)
  SigPcapLe* = fileSignature("pcap - le", "\xD4\xC3\xB2\xA1")
  SigPcapBe* = fileSignature("pcap - be", "\xA1\xB2\xC3\xD4")
  
  # Pcap w/ Nanosecond resolution (pcap)
  SigNsPcapLe* = fileSignature("pcap - ns le", "\x4D\x3C\xB2\xA1")
  SigNsPcapBe* = fileSignature("pcap - ns be", "\xA1\xB2\x3C\x4D")
  
  # Pcap next gen (pcapng)
  SigPcapNextGeneration* = fileSignature("pcap - ng", "\x0A\x0D\x0D\x0A")

  # RedHat Package Manager (rpm) package
  SigRpm* = fileSignature("SigRpm", "\xED\xAB\xEE\xDB")
  
  # SQLite (sqlitedb / sqlite / db)
  SigSqLite3* = fileSignature("SigSqLite3", "\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00")
  
  # Amazon Kindle Update Package (bin)
  SigKindleBin* = fileSignature("SigKindleBin", "\x53\x50\x30\x31")
  
  # ICO File (ico)
  SigIco* = fileSignature("SigIco", "\x00\x00\x01\x00")
  
  # Amiga backup data file (bac)
  SigBac* = fileSignature("SigBac", "\x42\x41\x43\x4B\x4D\x49\x4B\x45\x44\x49\x53\x4B")

  # Amiga backup index file
  SigIdx* = fileSignature("SigIdx", "\x49\x4E\x44\x58")

  # Bzip2
  SigBz2* = fileSignature("SigBz2", "\x42\x5A\x68")

  # Gif
  SigGif87a* = fileSignature("SigGif87a", "\x47\x49\x46\x38\x37\x61")
  SigGif89a* = fileSignature("SigGif89a", "\x47\x49\x46\x38\x39\x61")

  # Tiff (tif / tiff)
  SigTif* = fileSignature("SigTif", "\x49\x49\x2A\x00")
  SigTiff* = fileSignature("SigTiff", "\x4D\x4D\x00\x2A")

  SigCr2* = fileSignature("SigCr2", "\x49\x49\x2A\x00\x10\x00\x00\x00\x43\x52")

  SigCin* = fileSignature("SigCin", "\x80\x2A\x5F\xD7")

  # Zip (zip)
  SigZip* = fileSignature("SigZip", "\x50\x4B\x03\x04")
  SigZipEmpty * = fileSignature("SigZipEmpty ", "\x50\x4B\x05\x06")
  SigZipSpanned* = fileSignature("SigZipSpanned", "\x50\x4B\x07\x08")

  # Exe
  SigExe* = fileSignature("SigExe", "\x5A\x4D")

  SigExeMz* = fileSignature("SigExeMz", "\x4D\x5A")

  SigLzip* = fileSignature("SigLzip", "\x4C\x5A\x49\x50")

  SigRar1p5* = fileSignature("SigRar1p5", "\x52\x61\x72\x21\1A\x07\x00")

  SigRar5p0* = fileSignature("SigRar5p0", "\x52\x61\x72\x21\1A\x07\x01\x00")

  # Png
  SigPng* = fileSignature("SigPng", "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A")

  # Pdf
  SigPdf* = fileSignature("SigPdf", "\x25\x50\x44\x46\x2D")

  # Ogg
  SigOgg* = fileSignature("SigOgg", "\x4F\x67\x67\x53")

  # Photoshop
  SigPsd* = fileSignature("SigPsd", "\x38\x42\x50\x53")

  # Mp3
  SigMp3v0* = fileSignature("SigMp3v0", "\xFF\xFB")
  SigMp3v1* = fileSignature("SigMp3v1", "\xFF\xF3")
  SigMp3v2* = fileSignature("SigMp3v2", "\xFF\xF2")
  SigMp3v3* = fileSignature("SigMp3v3", "\x49\x44\x33")

  # Bmp images
  SigBmp* = fileSignature("SigBmp", "\x42\x4D")
  
  SigIso* = fileSignature("SigIso", "\x43\x44\x30\x30\x31")
  
  # FLAC
  SigFlac* = fileSignature("SigFlac", "\x66\x4C\x61\x43")

  # MIDI
  SigMidi* = fileSignature("SigMidi", "\x4D\x54\x68\x64")

  # Doc files
  SigDoc* = fileSignature("SigDoc", "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")

  SigDalvik* = fileSignature("SigDalvik", "\x64\x65\x78\x0A\x30\x33\x35\x00")

  SigVmdk* = fileSignature("SigVmdk", "\x4B\x44\x4D")

  SigCrx* = fileSignature("SigCrx", "\x43\x72\x32\x34")

  SigFh8* = fileSignature("SigFh8", "\x41\x47\x44\x33")

  # Dmg Apple disk image
  SigDmg* = fileSignature("SigDmg", "\x6B\x6F\x6C\x79")

  SigDat* = fileSignature("SigDat", "\x50\x4D\x4F\x43\x43\x4D\x4F\x43")

  # Nes roms
  SigNes* = fileSignature("SigNes", "\x4E\x45\x53\x1A")

  # 7z archives
  Sig7z* = fileSignature("Sig7z", "\x37\x7A\xBC\xAF\x27\x1C")

  # Tar (gz, xz, z)
  SigTarGz* = fileSignature("SigTarGz", "\x1F\x8B")
  SigTarXz* = fileSignature("SigTarXz", "\xFD\x37\x7A\x58\x5A\x00")
  SigTarZLzw* = fileSignature("SigTarZLzw", "\x1F\x9D")
  SigTarZLzh* = fileSignature("SigTarZLzh", "\x1F\xA0")

  # Mkv
  SigMkv* = fileSignature("SigMkv", "\x1A\x45\xDF\xA3")

  # Wasm
  SigWasm* = fileSignature("SigWasm", "\x00\x61\x73\x6D")

  SigSwfCws* = fileSignature("SigSwfCws", "\x43\x57\x53")

  SigSwfFws* = fileSignature("SigSwfFws", "\x46\x57\x53")

  # Deb packages
  SigDeb* = fileSignature("SigDeb", "\x21\x3C\x61\x72\x63\x68\x3E\x0A")

  SigRtf* = fileSignature("SigRtf", "\x7B\x5C\x72\x74\x66\x31")

  SigMpegv0* = fileSignature("SigMpegv0", "\x00\x00\x01\xBA")

  # Mp4 files
  SigMp4* = fileSignature("SigMp4", "\x66\x74\x79\x70\x69\x73\x6F\x6D")

  # Jpg (jpg, jpeg)
  SigJpg0* = fileSignature("SigJpg0", "\xff\xd8\xff\xdb")
  SigJpg1* = fileSignature("SigJpg1", "\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01")
  SigJpg2* = fileSignature("SigJpg2", "\xff\xd8\xff\xee")

  SigXcf* = fileSignature("SigXcf", "\x67\x69\x6D\x70\x20\x78\x63\x66")

  SigFlv* = fileSignature("SigFlv", "\x46\x4C\x56")

  SigDatWinReg* = fileSignature("SigDatWinReg", "\x72\x65\x67\x66")

  SigTxtUtf8* = fileSignature("SigTxtUtf8", "\xef\xbb\xbf")

  SigTxtUtf16Le* = fileSignature("SigTxtUtf16Le", "\xff\xfe")

  SigTxtUtf16Be* = fileSignature("SigTxtUtf16Be", "\xfe\xff")

  SigTxtUtf32Le* = fileSignature("SigTxtUtf32Le", "\xff\xfe\x00\x00")

  SigTxtUtf32Be* = fileSignature("SigTxtUtf32Be", "\x00\x00\xfe\xef")

  SigTxtScsu* = fileSignature("SigTxtScsu", "\x0e\xfe\xff")

  SigTxtUtf7* = fileSignature("SigTxtUtf7", "\x2b\x2f\x76\x38\x2b\x2f\x76\x39\x2b\x2f\x76\x2b\x2b\x2f\x76\x2f")

  SigUtfEbcdic* = fileSignature("SigUtfEbcdic", "\xdd\x73\x66\x73")

  SigPostScript* = fileSignature("SigPostScript", "\x25\x21\x50\x53")

  SigChm* = fileSignature("SigChm", "\x49\x54\x53\x46\x03\x00\x00\x00\x60\x00\x00\x00")

  SigAsf* = fileSignature("SigAsf", "\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c")

  SigSdi* = fileSignature("SigSdi", "\x24\x53\x44\x49\x30\x30\x30\x31")

  # Wav (wav) | 52 49 46 46 ?? ?? ?? ?? 57 41 56 45
  SigWav* = (
    "SigWav",
    @[(0, "\x52\x49\x46\x46"), (8, "\x57\x41\x56\x45")]
  )

  # Avi (avi) | 52 49 46 46 ?? ?? ?? ?? 41 56 49 20
  SigAvi* = (
    "SigAvi",
    @[(0, "\x52\x49\x46\x46"), (8, "\x41\x56\x49\x20")]
  )

  # SigMkv* = "\x1A\x45\xDF\xA3"
  SigWebm* = SigMkv
  SigMpgv0* = SigMpegv0
  SigJpg3* = (
    "SigJpg3", 
    @[
      (0, "\xff\xd8\xff\xe1"),
      (6, "\x45\x78\x69\x66\x00\x00")
    ]
  )
  SigJpeg0* = SigJpg0
  SigJpeg1* = SigJpg1
  SigJpeg2* = SigJpg2
  SigJpeg3* = SigJpg3

  # Advanced Systems Format (asf / wma / wmv)
  SigWma* = SigAsf
  SigWmv* = SigAsf

