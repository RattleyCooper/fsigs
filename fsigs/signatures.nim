

proc fileSignature(name: string, signature: string, offset: int = 0): tuple[name: string, temp: seq[tuple[offset: int, signature: string]]] =
  result = (
    name,
    @[(offset, signature)]
  )

const
  # Shebang at beginning of file.
  SigShebang* = fileSignature("SigShebang", "\x23\x21")

  # Pcap files (pcap)
  SigPcapLe* = fileSignature("SigPcapLe", "\xD4\xC3\xB2\xA1")
  SigPcapBe* = fileSignature("SigPcapBe", "\xA1\xB2\xC3\xD4")
  
  # Pcap w/ Nanosecond resolution (pcap)
  SigNsPcapLe* = fileSignature("SigNsPcapLe", "\x4D\x3C\xB2\xA1")
  SigNsPcapBe* = fileSignature("SigNsPcapBe", "\xA1\xB2\x3C\x4D")
  
  # Pcap next gen (pcapng)
  SigPcapNextGeneration* = fileSignature("SigPcapNextGeneration", "\x0A\x0D\x0D\x0A")

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

  # Rar
  SigRar1p5* = fileSignature("SigRar1p5", "\x52\x61\x72\x21\1A\x07\x00")
  SigRar5p0* = fileSignature("SigRar5p0", "\x52\x61\x72\x21\1A\x07\x01\x00")
  SigRar0* = fileSignature("SigRar0", "\x52\x61\x72\x21\x1a\x07\x00")
  SigRar1* = fileSignature("SigRar1", "\x52\x61\x72\x21\x1a\x07\x01\x00")

  # Executable & Linkable Format
  SigElf* = fileSignature("SigElf", "\x7f\x45\x4c\x46")

  # Png
  SigPng* = fileSignature("SigPng", "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A")

  # CP/M 3 and higher with overlays (com)
  SigCom* = fileSignature("SigCom", "\xc9")

  # Java Class File
  SigClass* = fileSignature("SigClass", "\xca\xfe\xba\xbe")

  # Mach-O Binary 32-bit, 64-bit
  SigMachO32* = fileSignature("SigMachO32", "\xfe\xed\xfa\xce")
  SigMachO64* = fileSignature("SigMachO64", "\xfe\xed\xfa\xcf")

  # Mach-O Reverse Byte 32-bit, 64-bit
  SigMachOR32* = fileSignature("SigMachOR32", "\xce\xfa\xed\xfe")
  SigMachOR64* = fileSignature("SigMachOR64", "\xcf\xfa\xed\xfe")

  # Jks JavakeyStore
  SigJks* = fileSignature("SigJks", "\xfe\xed\xfe\xed")

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
  SigDib* = SigBmp
  
  # ISO9660 CD/DVD image file (iso)
  SigIso* = fileSignature("SigIso", "\x43\x44\x30\x30\x31")
  
  # Flexible Image Transport System (fits)
  SigFits* = fileSignature("SigFits", "\x53\x49\x4D\x50\x4C\x45\x20\x20\x3D\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x54")

  # Free Lossless Audio Codec (flac)
  SigFlac* = fileSignature("SigFlac", "\x66\x4C\x61\x43")

  # MIDI sound file (midi, mid)
  SigMidi* = fileSignature("SigMidi", "\x4D\x54\x68\x64")
  SigMid* = SigMidi

  # Compound File Binary Format, a container format used for document by older versions of Microsoft Office.
  # (doc, xls, ppt, msg)
  SigDoc* = fileSignature("SigDoc", "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
  SigXls* = SigDoc
  SigPpt* = SigDoc
  SigMsg* = SigDoc

  # Dalvid Executable (dex)
  SigDex* = fileSignature("SigDex", "\x64\x65\x78\x0A\x30\x33\x35\x00")

  # VMDK files (vmdk)
  SigVmdk* = fileSignature("SigVmdk", "\x4B\x44\x4D")

  # Google Chrome extension or packaged app (crx)
  SigCrx* = fileSignature("SigCrx", "\x43\x72\x32\x34")
  
  # Google WebP image file
  SigWebP* = (
    "SigWebP", 
    @[
      (0, "\x52\x49\x46\x46"),
      (8, "\x57\x45\x42\x50")
    ]
  )

  # Freehand 8 document (fh8)
  SigFh8* = fileSignature("SigFh8", "\x41\x47\x44\x33")

  # Apple disk image (dmg)
  SigDmg* = fileSignature("SigDmg", "\x6B\x6F\x6C\x79")

  # Appleworks 5 Document (cwk)
  SigCwk5v0* = fileSignature("SigCwk5v0", "\x05\x07\x00\x00\x42\x4F\x42\x4F")
  SigCwk5v1* = fileSignature("SigCwk5v1", "\x05\x07\x00\x00\x00\x00\x00\x00")
  SigCwk5v2* = fileSignature("SigCwk5v2", "\x00\x00\x00\x00\x00\x01")

  # Appleworks 6 Document (cwk)
  SigCwk6v0* = fileSignature("SigCwk6v0", "\x06\x07\xE1\x00\x42\x4F\x42\x4F")
  SigCwk6v1* = fileSignature("SigCwk6v1", "\x06\x07\xE1\x00\x00\x00\x00\x00")
  SigCwk6v2* = fileSignature("SigCwk6v2", "\x00\x00\x00\x00\x00\x01")

  # Roxio Toast disc image file (toast)
  SigToast0* = fileSignature("SigToast0", "\x45\x52\x02\x00\x00\x00")
  SigToast1* = fileSignature("SigToast1", "\x8b\x45\x52\x02\x00\x00\x00")

  # 3rd Generation Partnership Project 3GPP and 3GPP2 (3gp, 3gp2)
  Sig3gp* = fileSignature("Sig3gp", "\x66\x74\x79\x70\x33\x67", 4)
  Sig3gp2* = fileSignature("Sig3gp2", "\x66\x74\x79\x70\x33\x67", 4)

  # Oar file archive format (oar)
  SigOar* = fileSignature("SigOar", "\x4f\x41\x52")

  # Open source portable voxel file (tox)  
  SigTox* = fileSignature("SigTox", "\x74\x6f\x78\x33")

  # Magic Lantern Video (mlv)
  SigMlv* = fileSignature("SigMlv", "\x4d\x4c\x56\x49")

  # Windows Update Binary Delta Compression file
  SigUbdc0* = fileSignature("SigUbdc0", "\x44\x43\x4d\x01\x50\x41\x33\x30")
  SigUbdc1* = fileSignature("SigUbdc1", "\x50\x41\x33\x30")

  # Lz4 Frame Format
  SigLz4* = fileSignature("SigLz4", "\x04\x22\x4d\x18")

  # Microsoft Cabinet File (cab)
  SigCab* = fileSignature("SigCab", "\x4d\x53\x43\x46")

  # Free Lossless Image Format (flif)
  SigFlif* = fileSignature("SigFlif", "\x46\x4c\x49\x46")

  # "SEAN : Session Analysis" Training file. (stg)
  SigStg* = fileSignature("SigStg", "\x4d\x49\x4c\x20")

  # DjVu document (djvu, djv)
  SigDjvu* = fileSignature("SigDjvu", "\x46\x4c\x49\x46")
  SigDjv* = SigDjvu

  # eXtensible Markup Language (xml)
  SigXml0* = fileSignature("SigXml0", "\x3c\x3f\x78\x6d\x6c\x20")
  SigXml1* = fileSignature("SigXml1", "\x3C\x00\x3F\x00\x78\x00\x6D\x00\x6C\x00\x20")
  SigXml2* = fileSignature("SigXml2", "\x00\x3C\x00\x3F\x00\x78\x00\x6D\x00\x6C\x00\x20")
  SigXml3* = fileSignature("SigXml3", "\x3C\x00\x00\x00\x3F\x00\x00\x00\x78\x00\x00\x00\x6D\x00\x00\x00\x6C\x00\x00\x00\x20\x00\x00\x00")
  SigXml4* = fileSignature("SigXml4", "\x00\x00\x00\x3C\x00\x00\x00\x3F\x00\x00\x00\x78\x00\x00\x00\x6D\x00\x00\x00\x6C\x00\x00\x00\x20")
  SigXml5* = fileSignature("SigXml5", "\x4C\x6F\xA7\x94\x93\x40")

  # WOFF File Format 1.0 and 2.0 (woff, woff2)
  SigWoff* = fileSignature("SigWoff", "\x77\x4f\x46\x46")
  SigWoff2* = fileSignature("SigWoff2", "\x77\x4f\x46\x32")

  # DER encoded X.509 certificate (der)
  SigDer* = fileSignature("SigDer", "\x30\x82")
  
  # DICOM Medical File Format (dcm)
  SigDcm* = fileSignature("SigDcm", "\x44\x49\x43\x4d", 128)

  # Lepton compressed jpeg image (lep)
  SigLep* = fileSignature("SigLep", "\xcf\x84\x01")

  # U-Boot / uImage Universal Bootloader. Das U-Boot Universal Boot Loader
  SigUBoot* = fileSignature("SigUBoot", "\x27\x05\x19\x56")

  SigDat* = fileSignature("SigDat", "\x50\x4D\x4F\x43\x43\x4D\x4F\x43")

  # Nes roms
  SigNes* = fileSignature("SigNes", "\x4E\x45\x53\x1A")

  # 7z archives
  Sig7z* = fileSignature("Sig7z", "\x37\x7A\xBC\xAF\x27\x1C")

  # Tar (gz, xz, z, tar)
  SigTarGz* = fileSignature("SigTarGz", "\x1F\x8B")
  SigTarXz* = fileSignature("SigTarXz", "\xFD\x37\x7A\x58\x5A\x00")
  SigTarZLzw* = fileSignature("SigTarZLzw", "\x1F\x9D")
  SigTarZLzh* = fileSignature("SigTarZLzh", "\x1F\xA0")
  SigTar0* = fileSignature("SigTar0", "\x75\x73\x74\x61\x72\x00\x30\x30", 257)
  SigTar1* = fileSignature("SigTar1", "\x75\x73\x74\x61\x72\x20\x20\x00", 257)

  # Matroska media container, including WebM (mkv, mks, mk3d, webm)
  SigMkv* = fileSignature("SigMkv", "\x1A\x45\xDF\xA3")
  SigMka* = SigMkv
  SigMks* = SigMkv
  SigMk3d* = SigMkv
  SigWebm* = SigMkv

  # Wasm
  SigWasm* = fileSignature("SigWasm", "\x00\x61\x73\x6D")

  # Adobe Flash (swf)
  SigSwfCws* = fileSignature("SigSwfCws", "\x43\x57\x53")
  SigSwfFws* = fileSignature("SigSwfFws", "\x46\x57\x53")

  # Debian linux packages (deb)
  SigDeb* = fileSignature("SigDeb", "\x21\x3C\x61\x72\x63\x68\x3E\x0A")

  # Rich Text Format (rtf)
  SigRtf* = fileSignature("SigRtf", "\x7B\x5C\x72\x74\x66\x31")

  # MPEG Program Stream (mpeg, mpg, vob, m2p)
  SigMpegP* = fileSignature("SigMpegP", "\x00\x00\x01\xBA")
  SigMpgP* = SigMpegP
  SigVob* = SigMpegP
  SigM2p* = SigMpegP

  # MPEG Video 1 and 2 (mpg, mpeg)
  SigMpeg* = fileSignature("SigMpeg", "\x00\x00\x01\xB3")
  SigMpg* = SigMpeg

  # Mp4 files
  SigMp4* = fileSignature("SigMp4", "\x66\x74\x79\x70\x69\x73\x6F\x6D", 4)

  # Zlib archives (zlib)
  SigZlib0* = fileSignature("SigZlib0", "\x78\x01") # no compression (no preset dictionary)
  SigZlib1* = fileSignature("SigZlib1", "\x78\x5e") # Best speed (no preset dictionary)
  SigZlib2* = fileSignature("SigZlib2", "\x78\x9c") # Default Compression (no preset dictionary) 
  SigZlib3* = fileSignature("SigZlib3", "\x78\xda") # Best Compression (no preset dictionary) 
  SigZlib4* = fileSignature("SigZlib4", "\x78\x20") # No Compression (with preset dictionary) 
  SigZlib5* = fileSignature("SigZlib5", "\x78\x7d") # Best speed (with preset dictionary) 
  SigZlib6* = fileSignature("SigZlib6", "\x78\xbb") # Default Compression (with preset dictionary) 
  SigZlib7* = fileSignature("SigZlib7", "\x78\xf9") # Best Compression (with preset dictionary) 

  # LZFSE - Lempel-Ziv style data compression algorithm using 
  # Finite State Entropy coding. OSS by Apple
  # (lzfse)
  SigLzfse* = fileSignature("SigLzfse", "\x62\x76\x78\x32")
  
  # Apache ORC - optimized row columnar file format (orc)
  SigOrc* = fileSignature("SigOrc", "\x4f\x52\x43")

  # Apache Avro binary file format (avro)
  SigAvro* = fileSignature("SigAvro", "\x4f\x62\x6a\x01")

  # RCFile columnar file format (rc)
  SigRc* = fileSignature("SigRc", "\x53\x45\x51\x36")

  # Lua bytecode (luac)
  SigLuac* = fileSignature("SigLuac", "\x1b\x4c\x75\x61")

  # Python bytecode (pyc) 61 0d 0d 0a 00 00 00 00
  SigPyc* = fileSignature("SigPyc", "\x61\x0d\x0d\x0a\x00\x00\x00\x00")

  # macOS file alias (alias)
  SigAlias* = fileSignature("SigAlias", "\x62\x6f\x6f\x6b\x00\x00\x00\x00\x6d\x61\x72\x6b\x00\x00\x00\x00")
  
  # Email Message var5 (eml)
  SigEml* = fileSignature("SigEml", "\x52\x65\x63\x65\x69\x76\x65\x64\x3a")

  # PGP file (pgp)
  SigPgp* = (
    "SigPgp", 
    @[
      (0, "\x85"),
      (3, "\x03")
    ]
  )

  # Vpk file used to store game data for some Source Engine games (vpk)
  SigVpk* = fileSignature("SigVpk", "\x34\x12\xaa\x55")

  # AFF (aff)
  SigAff* = fileSignature("SigAff", "\x41\x46\x46")

  # Jpg (jpg, jpeg)
  SigJpg0* = fileSignature("SigJpg0", "\xFF\xD8\xFF\xDB")
  SigJpg1* = fileSignature("SigJpg1", "\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01")
  SigJpg2* = fileSignature("SigJpg2", "\xFF\xD8\xFF\xEE")
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

  SigXcf* = fileSignature("SigXcf", "\x67\x69\x6D\x70\x20\x78\x63\x66")

  SigFlv* = fileSignature("SigFlv", "\x46\x4C\x56")

  # Windows Registry File (dat)
  SigDatWinReg* = fileSignature("SigDatWinReg", "\x72\x65\x67\x66")

  # Utf encoded
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

  # System Deployment Image, a disk image format used by Microsoft
  SigSdi* = fileSignature("SigSdi", "\x24\x53\x44\x49\x30\x30\x30\x31")

  # Microsoft TAPE Format
  SigTape* = fileSignature("SigTape", "\x54\x41\x50\x45")

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

  # Iff interleaved bitmap image (ilbm, lbm, ibm, iff)
  SigIlbm* = (
    "SigIlbm",
    @[
      (0, "\x46\x4f\x52\x4d"),
      (8, "\x49\x4c\x42\x4d")
    ]
  )
  SigLbm* = SigIlbm
  SigIbm* = SigIlbm
  SigIff* = SigIlbm

  # Iff 8-bit sampled voice
  Sig8svx* = (
    "Sig8svx",
    @[
      (0, "\x46\x4f\x52\x4d"),
      (8, "\x38\x53\x56\x58")
    ]
  )
  Sig8sv* = Sig8svx
  SigSvx* = Sig8svx
  SigSnd* = Sig8svx
  Sig8svIff* = Sig8svx

  # Advanced Systems Format (asf / wma / wmv)
  SigAsf* = fileSignature("SigAsf", "\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c")
  SigWma* = SigAsf
  SigWmv* = SigAsf

