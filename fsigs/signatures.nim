import fsigs


proc fileSignature*(id: FileSignatures, signature: string, offset: int = 0): FileSignature =
  result = (
    id,
    @[(offset, signature)]
  )

proc `<-`(fs: FileSignature, id: FileSignatures): FileSignature =
  ## Patch file signature so it's "id" matches given "id"
  #

  result.id = id
  result.temp = fs.temp

const
  # Shebang at beginning of file.
  SigShebang* = fileSignature(fSigShebang, "\x23\x21")

  # Pcap files (pcap)
  SigPcapLe* = fileSignature(fSigPcapLe, "\xD4\xC3\xB2\xA1")
  SigPcapBe* = fileSignature(fSigPcapBe, "\xA1\xB2\xC3\xD4")
  
  # Pcap w/ Nanosecond resolution (pcap)
  SigNsPcapLe* = fileSignature(fSigNsPcapLe, "\x4D\x3C\xB2\xA1")
  SigNsPcapBe* = fileSignature(fSigNsPcapBe, "\xA1\xB2\x3C\x4D")
  
  # Pcap next gen (pcapng)
  SigPcapNextGeneration* = fileSignature(fSigPcapNextGeneration, "\x0A\x0D\x0D\x0A")

  # RedHat Package Manager (rpm) package
  SigRpm* = fileSignature(fSigRpm, "\xED\xAB\xEE\xDB")
  
  # SQLite (sqlitedb / sqlite / db)
  SigSqLite3* = fileSignature(fSigSqLite3, "\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00")
  
  # Amazon Kindle Update Package (bin)
  SigKindleBin* = fileSignature(fSigKindleBin, "\x53\x50\x30\x31")
  
  # ICO File (ico)
  SigIco* = fileSignature(fSigIco, "\x00\x00\x01\x00")
  
  # Amiga backup data file (bac)
  SigBac* = fileSignature(fSigBac, "\x42\x41\x43\x4B\x4D\x49\x4B\x45\x44\x49\x53\x4B")

  # Amiga backup index file
  SigIdx* = fileSignature(fSigIdx, "\x49\x4E\x44\x58")

  # Bzip2
  SigBz2* = fileSignature(fSigBz2, "\x42\x5A\x68")

  # Gif
  SigGif87a* = fileSignature(fSigGif87a, "\x47\x49\x46\x38\x37\x61")
  SigGif89a* = fileSignature(fSigGif89a, "\x47\x49\x46\x38\x39\x61")

  # Tiff (tif / tiff)
  SigTif* = fileSignature(fSigTif, "\x49\x49\x2A\x00")
  SigTiff* = fileSignature(fSigTiff, "\x4D\x4D\x00\x2A")

  SigCr2* = fileSignature(fSigCr2, "\x49\x49\x2A\x00\x10\x00\x00\x00\x43\x52")

  SigCin* = fileSignature(fSigCin, "\x80\x2A\x5F\xD7")

  # Zip (zip)
  SigZip* = fileSignature(fSigZip, "\x50\x4B\x03\x04")
  SigZipEmpty * = fileSignature(fSigZipEmpty , "\x50\x4B\x05\x06")
  SigZipSpanned* = fileSignature(fSigZipSpanned, "\x50\x4B\x07\x08")

  # Exe
  SigExe* = fileSignature(fSigExe, "\x5A\x4D")

  SigExeMz* = fileSignature(fSigExeMz, "\x4D\x5A")

  SigLzip* = fileSignature(fSigLzip, "\x4C\x5A\x49\x50")

  # Rar
  SigRar1p5* = fileSignature(fSigRar1p5, "\x52\x61\x72\x21\1A\x07\x00")
  SigRar5p0* = fileSignature(fSigRar5p0, "\x52\x61\x72\x21\1A\x07\x01\x00")
  SigRar0* = fileSignature(fSigRar0, "\x52\x61\x72\x21\x1a\x07\x00")
  SigRar1* = fileSignature(fSigRar1, "\x52\x61\x72\x21\x1a\x07\x01\x00")

  # Executable & Linkable Format
  SigElf* = fileSignature(fSigElf, "\x7f\x45\x4c\x46")

  # Png
  SigPng* = fileSignature(fSigPng, "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A")

  # CP/M 3 and higher with overlays (com)
  SigCom* = fileSignature(fSigCom, "\xc9")

  # Java Class File
  SigClass* = fileSignature(fSigClass, "\xca\xfe\xba\xbe")

  # Mach-O Binary 32-bit, 64-bit
  SigMachO32* = fileSignature(fSigMachO32, "\xfe\xed\xfa\xce")
  SigMachO64* = fileSignature(fSigMachO64, "\xfe\xed\xfa\xcf")

  # Mach-O Reverse Byte 32-bit, 64-bit
  SigMachOR32* = fileSignature(fSigMachOR32, "\xce\xfa\xed\xfe")
  SigMachOR64* = fileSignature(fSigMachOR64, "\xcf\xfa\xed\xfe")

  # Jks JavakeyStore
  SigJks* = fileSignature(fSigJks, "\xfe\xed\xfe\xed")

  # Pdf
  SigPdf* = fileSignature(fSigPdf, "\x25\x50\x44\x46\x2D")

  # Ogg
  SigOgg* = fileSignature(fSigOgg, "\x4F\x67\x67\x53")

  # Photoshop
  SigPsd* = fileSignature(fSigPsd, "\x38\x42\x50\x53")

  # Mp3
  SigMp3v0* = fileSignature(fSigMp3v0, "\xFF\xFB")
  SigMp3v1* = fileSignature(fSigMp3v1, "\xFF\xF3")
  SigMp3v2* = fileSignature(fSigMp3v2, "\xFF\xF2")
  SigMp3v3* = fileSignature(fSigMp3v3, "\x49\x44\x33")

  # Bmp images
  SigBmp* = fileSignature(fSigBmp, "\x42\x4D")
  SigDib* = SigBmp <- fSigDib
  
  # ISO9660 CD/DVD image file (iso)
  SigIso* = fileSignature(fSigIso, "\x43\x44\x30\x30\x31")
  
  # Flexible Image Transport System (fits)
  SigFits* = fileSignature(fSigFits, "\x53\x49\x4D\x50\x4C\x45\x20\x20\x3D\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x54")

  # Free Lossless Audio Codec (flac)
  SigFlac* = fileSignature(fSigFlac, "\x66\x4C\x61\x43")

  # MIDI sound file (midi, mid)
  SigMidi* = fileSignature(fSigMidi, "\x4D\x54\x68\x64")
  SigMid* = SigMidi <- fSigMid

  # Compound File Binary Format, a container format used for document by older versions of Microsoft Office.
  # (doc, xls, ppt, msg)
  SigDoc* = fileSignature(fSigDoc, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
  SigXls* = SigDoc <- fSigXls
  SigPpt* = SigDoc <- fSigPpt
  SigMsg* = SigDoc <- fSigMsg

  # Dalvid Executable (dex)
  SigDex* = fileSignature(fSigDex, "\x64\x65\x78\x0A\x30\x33\x35\x00")

  # VMDK files (vmdk)
  SigVmdk* = fileSignature(fSigVmdk, "\x4B\x44\x4D")

  # Google Chrome extension or packaged app (crx)
  SigCrx* = fileSignature(fSigCrx, "\x43\x72\x32\x34")
  
  # Google WebP image file
  SigWebP* = (
    fSigWebP, 
    @[
      (0, "\x52\x49\x46\x46"),
      (8, "\x57\x45\x42\x50")
    ]
  )

  # Freehand 8 document (fh8)
  SigFh8* = fileSignature(fSigFh8, "\x41\x47\x44\x33")

  # Apple disk image (dmg)
  SigDmg* = fileSignature(fSigDmg, "\x6B\x6F\x6C\x79")

  # Appleworks 5 Document (cwk)
  SigCwk5v0* = fileSignature(fSigCwk5v0, "\x05\x07\x00\x00\x42\x4F\x42\x4F")
  SigCwk5v1* = fileSignature(fSigCwk5v1, "\x05\x07\x00\x00\x00\x00\x00\x00")
  SigCwk5v2* = fileSignature(fSigCwk5v2, "\x00\x00\x00\x00\x00\x01")

  # Appleworks 6 Document (cwk)
  SigCwk6v0* = fileSignature(fSigCwk6v0, "\x06\x07\xE1\x00\x42\x4F\x42\x4F")
  SigCwk6v1* = fileSignature(fSigCwk6v1, "\x06\x07\xE1\x00\x00\x00\x00\x00")
  SigCwk6v2* = fileSignature(fSigCwk6v2, "\x00\x00\x00\x00\x00\x01")

  # Roxio Toast disc image file (toast)
  SigToast0* = fileSignature(fSigToast0, "\x45\x52\x02\x00\x00\x00")
  SigToast1* = fileSignature(fSigToast1, "\x8b\x45\x52\x02\x00\x00\x00")

  # 3rd Generation Partnership Project 3GPP and 3GPP2 (3gp, 3gp2)
  Sig3gp* = fileSignature(fSig3gp, "\x66\x74\x79\x70\x33\x67", 4)
  Sig3gp2* = Sig3gp <- fSig3gp2

  # Oar file archive format (oar)
  SigOar* = fileSignature(fSigOar, "\x4f\x41\x52")

  # Open source portable voxel file (tox)  
  SigTox* = fileSignature(fSigTox, "\x74\x6f\x78\x33")

  # Magic Lantern Video (mlv)
  SigMlv* = fileSignature(fSigMlv, "\x4d\x4c\x56\x49")

  # Windows Update Binary Delta Compression file
  SigUbdc0* = fileSignature(fSigUbdc0, "\x44\x43\x4d\x01\x50\x41\x33\x30")
  SigUbdc1* = fileSignature(fSigUbdc1, "\x50\x41\x33\x30")

  # Lz4 Frame Format
  SigLz4* = fileSignature(fSigLz4, "\x04\x22\x4d\x18")

  # Microsoft Cabinet File (cab)
  SigCab* = fileSignature(fSigCab, "\x4d\x53\x43\x46")

  # Free Lossless Image Format (flif)
  SigFlif* = fileSignature(fSigFlif, "\x46\x4c\x49\x46")

  # "SEAN : Session Analysis" Training file. (stg)
  SigStg* = fileSignature(fSigStg, "\x4d\x49\x4c\x20")

  # DjVu document (djvu, djv)
  SigDjvu* = fileSignature(fSigDjvu, "\x46\x4c\x49\x46")
  SigDjv* = SigDjvu <- fSigDjv

  # eXtensible Markup Language (xml)
  SigXml0* = fileSignature(fSigXml0, "\x3c\x3f\x78\x6d\x6c\x20")
  SigXml1* = fileSignature(fSigXml1, "\x3C\x00\x3F\x00\x78\x00\x6D\x00\x6C\x00\x20")
  SigXml2* = fileSignature(fSigXml2, "\x00\x3C\x00\x3F\x00\x78\x00\x6D\x00\x6C\x00\x20")
  SigXml3* = fileSignature(fSigXml3, "\x3C\x00\x00\x00\x3F\x00\x00\x00\x78\x00\x00\x00\x6D\x00\x00\x00\x6C\x00\x00\x00\x20\x00\x00\x00")
  SigXml4* = fileSignature(fSigXml4, "\x00\x00\x00\x3C\x00\x00\x00\x3F\x00\x00\x00\x78\x00\x00\x00\x6D\x00\x00\x00\x6C\x00\x00\x00\x20")
  SigXml5* = fileSignature(fSigXml5, "\x4C\x6F\xA7\x94\x93\x40")

  # WOFF File Format 1.0 and 2.0 (woff, woff2)
  SigWoff* = fileSignature(fSigWoff, "\x77\x4f\x46\x46")
  SigWoff2* = fileSignature(fSigWoff2, "\x77\x4f\x46\x32")

  # DER encoded X.509 certificate (der)
  SigDer* = fileSignature(fSigDer, "\x30\x82")
  
  # DICOM Medical File Format (dcm)
  SigDcm* = fileSignature(fSigDcm, "\x44\x49\x43\x4d", 128)

  # Lepton compressed jpeg image (lep)
  SigLep* = fileSignature(fSigLep, "\xcf\x84\x01")

  # U-Boot / uImage Universal Bootloader. Das U-Boot Universal Boot Loader
  SigUBoot* = fileSignature(fSigUBoot, "\x27\x05\x19\x56")

  SigDat* = fileSignature(fSigDat, "\x50\x4D\x4F\x43\x43\x4D\x4F\x43")

  # Nes roms
  SigNes* = fileSignature(fSigNes, "\x4E\x45\x53\x1A")

  # 7z archives
  Sig7z* = fileSignature(fSig7z, "\x37\x7A\xBC\xAF\x27\x1C")

  # Tar (gz, xz, z, tar)
  SigTarGz* = fileSignature(fSigTarGz, "\x1F\x8B")
  SigTarXz* = fileSignature(fSigTarXz, "\xFD\x37\x7A\x58\x5A\x00")
  SigTarZLzw* = fileSignature(fSigTarZLzw, "\x1F\x9D")
  SigTarZLzh* = fileSignature(fSigTarZLzh, "\x1F\xA0")
  SigTar0* = fileSignature(fSigTar0, "\x75\x73\x74\x61\x72\x00\x30\x30", 257)
  SigTar1* = fileSignature(fSigTar1, "\x75\x73\x74\x61\x72\x20\x20\x00", 257)

  # Matroska media container, including WebM (mkv, mks, mk3d, webm)
  SigMkv* = fileSignature(fSigMkv, "\x1A\x45\xDF\xA3")
  SigMka* = SigMkv <- fSigMka
  SigMks* = SigMkv <- fSigMks
  SigMk3d* = SigMkv <- fSigMk3d
  SigWebm* = SigMkv <- fSigWebm

  # Wasm
  SigWasm* = fileSignature(fSigWasm, "\x00\x61\x73\x6D")

  # Adobe Flash (swf)
  SigSwfCws* = fileSignature(fSigSwfCws, "\x43\x57\x53")
  SigSwfFws* = fileSignature(fSigSwfFws, "\x46\x57\x53")

  # Debian linux packages (deb)
  SigDeb* = fileSignature(fSigDeb, "\x21\x3C\x61\x72\x63\x68\x3E\x0A")

  # Rich Text Format (rtf)
  SigRtf* = fileSignature(fSigRtf, "\x7B\x5C\x72\x74\x66\x31")

  # MPEG Program Stream (mpeg, mpg, vob, m2p)
  SigMpegP* = fileSignature(fSigMpegP, "\x00\x00\x01\xBA")
  SigMpgP* = SigMpegP <- fSigMpgP
  SigVob* = SigMpegP <- fSigVob
  SigM2p* = SigMpegP <- fSigM2p

  # MPEG Video 1 and 2 (mpg, mpeg)
  SigMpeg* = fileSignature(fSigMpeg, "\x00\x00\x01\xB3")
  SigMpg* = SigMpeg <- fSigMpg

  # Mp4 files
  SigMp4* = fileSignature(fSigMp4, "\x66\x74\x79\x70\x69\x73\x6F\x6D", 4)

  # Zlib archives (zlib)
  SigZlib0* = fileSignature(fSigZlib0, "\x78\x01") # no compression (no preset dictionary)
  SigZlib1* = fileSignature(fSigZlib1, "\x78\x5e") # Best speed (no preset dictionary)
  SigZlib2* = fileSignature(fSigZlib2, "\x78\x9c") # Default Compression (no preset dictionary) 
  SigZlib3* = fileSignature(fSigZlib3, "\x78\xda") # Best Compression (no preset dictionary) 
  SigZlib4* = fileSignature(fSigZlib4, "\x78\x20") # No Compression (with preset dictionary) 
  SigZlib5* = fileSignature(fSigZlib5, "\x78\x7d") # Best speed (with preset dictionary) 
  SigZlib6* = fileSignature(fSigZlib6, "\x78\xbb") # Default Compression (with preset dictionary) 
  SigZlib7* = fileSignature(fSigZlib7, "\x78\xf9") # Best Compression (with preset dictionary) 

  # LZFSE - Lempel-Ziv style data compression algorithm using 
  # Finite State Entropy coding. OSS by Apple
  # (lzfse)
  SigLzfse* = fileSignature(fSigLzfse, "\x62\x76\x78\x32")
  
  # Apache ORC - optimized row columnar file format (orc)
  SigOrc* = fileSignature(fSigOrc, "\x4f\x52\x43")

  # Apache Avro binary file format (avro)
  SigAvro* = fileSignature(fSigAvro, "\x4f\x62\x6a\x01")

  # RCFile columnar file format (rc)
  SigRc* = fileSignature(fSigRc, "\x53\x45\x51\x36")

  # Lua bytecode (luac)
  SigLuac* = fileSignature(fSigLuac, "\x1b\x4c\x75\x61")

  # Python bytecode (pyc) 61 0d 0d 0a 00 00 00 00
  SigPyc* = fileSignature(fSigPyc, "\x61\x0d\x0d\x0a\x00\x00\x00\x00")

  # macOS file alias (alias)
  SigAlias* = fileSignature(fSigAlias, "\x62\x6f\x6f\x6b\x00\x00\x00\x00\x6d\x61\x72\x6b\x00\x00\x00\x00")
  
  # Email Message var5 (eml)
  SigEml* = fileSignature(fSigEml, "\x52\x65\x63\x65\x69\x76\x65\x64\x3a")

  # PGP file (pgp)
  SigPgp* = (
    fSigPgp, 
    @[
      (0, "\x85"),
      (3, "\x03")
    ]
  )

  # Vpk file used to store game data for some Source Engine games (vpk)
  SigVpk* = fileSignature(fSigVpk, "\x34\x12\xaa\x55")

  # AFF (aff)
  SigAff* = fileSignature(fSigAff, "\x41\x46\x46")

  # Jpg (jpg, jpeg)
  SigJpg0* = fileSignature(fSigJpg0, "\xFF\xD8\xFF\xDB")
  SigJpg1* = fileSignature(fSigJpg1, "\xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01")
  SigJpg2* = fileSignature(fSigJpg2, "\xFF\xD8\xFF\xEE")
  SigJpg3* = (
    fSigJpg3, 
    @[
      (0, "\xff\xd8\xff\xe1"),
      (6, "\x45\x78\x69\x66\x00\x00")
    ]
  )
  SigJpeg0* = SigJpg0 <- fSigJpeg0
  SigJpeg1* = SigJpg1 <- fSigJpeg1
  SigJpeg2* = SigJpg2 <- fSigJpeg2
  SigJpeg3* = SigJpg3 <- fSigJpeg3

  SigXcf* = fileSignature(fSigXcf, "\x67\x69\x6D\x70\x20\x78\x63\x66")

  SigFlv* = fileSignature(fSigFlv, "\x46\x4C\x56")

  # Windows Registry File (dat)
  SigDatWinReg* = fileSignature(fSigDatWinReg, "\x72\x65\x67\x66")

  # Utf encoded
  SigTxtUtf8* = fileSignature(fSigTxtUtf8, "\xef\xbb\xbf")
  SigTxtUtf16Le* = fileSignature(fSigTxtUtf16Le, "\xff\xfe")
  SigTxtUtf16Be* = fileSignature(fSigTxtUtf16Be, "\xfe\xff")
  SigTxtUtf32Le* = fileSignature(fSigTxtUtf32Le, "\xff\xfe\x00\x00")
  SigTxtUtf32Be* = fileSignature(fSigTxtUtf32Be, "\x00\x00\xfe\xef")

  SigTxtScsu* = fileSignature(fSigTxtScsu, "\x0e\xfe\xff")

  SigTxtUtf7* = fileSignature(fSigTxtUtf7, "\x2b\x2f\x76\x38\x2b\x2f\x76\x39\x2b\x2f\x76\x2b\x2b\x2f\x76\x2f")

  SigUtfEbcdic* = fileSignature(fSigUtfEbcdic, "\xdd\x73\x66\x73")

  SigPostScript* = fileSignature(fSigPostScript, "\x25\x21\x50\x53")

  SigChm* = fileSignature(fSigChm, "\x49\x54\x53\x46\x03\x00\x00\x00\x60\x00\x00\x00")

  # System Deployment Image, a disk image format used by Microsoft
  SigSdi* = fileSignature(fSigSdi, "\x24\x53\x44\x49\x30\x30\x30\x31")

  # Microsoft TAPE Format
  SigTape* = fileSignature(fSigTape, "\x54\x41\x50\x45")

  # Wav (wav) | 52 49 46 46 ?? ?? ?? ?? 57 41 56 45
  SigWav* = (
    fSigWav,
    @[(0, "\x52\x49\x46\x46"), (8, "\x57\x41\x56\x45")]
  )

  # Avi (avi) | 52 49 46 46 ?? ?? ?? ?? 41 56 49 20
  SigAvi* = (
    fSigAvi,
    @[(0, "\x52\x49\x46\x46"), (8, "\x41\x56\x49\x20")]
  )

  # Iff interleaved bitmap image (ilbm, lbm, ibm, iff)
  SigIlbm* = (
    fSigIlbm,
    @[
      (0, "\x46\x4f\x52\x4d"),
      (8, "\x49\x4c\x42\x4d")
    ]
  )
  SigLbm* = SigIlbm <- fSigLbm
  SigIbm* = SigIlbm <- fSigIbm
  SigIff* = SigIlbm <- fSigIff

  # Iff 8-bit sampled voice
  Sig8svx* = (
    fSig8svx,
    @[
      (0, "\x46\x4f\x52\x4d"),
      (8, "\x38\x53\x56\x58")
    ]
  )
  Sig8sv* = Sig8svx <- fSig8sv
  SigSvx* = Sig8svx <- fSigSvx
  SigSnd* = Sig8svx <- fSigSnd
  Sig8svIff* = Sig8svx <- fSig8svIff

  # Advanced Systems Format (asf / wma / wmv)
  SigAsf* = fileSignature(fSigAsf, "\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c")
  SigWma* = SigAsf <- fSigWma
  SigWmv* = SigAsf <- fSigWmv

const 
  AllFileSignatures* = @[
    SigShebang,
    SigPcapLe,
    SigPcapBe,
    SigNsPcapLe,
    SigNsPcapBe,
    SigPcapNextGeneration,
    SigRpm,
    SigSqLite3,
    SigKindleBin,
    SigIco,
    SigBac,
    SigIdx,
    SigBz2,
    SigGif87a,
    SigGif89a,
    SigTif,
    SigTiff,
    SigCr2,
    SigCin,
    SigZip,
    SigZipEmpty,
    SigZipSpanned,
    SigExe,
    SigExeMz,
    SigLzip,
    SigRar1p5,
    SigRar5p0,
    SigRar0,
    SigRar1,
    SigElf,
    SigPng,
    SigCom,
    SigClass,
    SigMachO32,
    SigMachO64,
    SigMachOR32,
    SigMachOR64,
    SigJks,
    SigPdf,
    SigOgg,
    SigPsd,
    SigMp3v0,
    SigMp3v1,
    SigMp3v2,
    SigMp3v3,
    SigBmp,
    SigDib,
    SigIso,
    SigFits,
    SigFlac,
    SigMidi,
    SigMid,
    SigDoc,
    SigXls,
    SigPpt,
    SigMsg,
    SigDex,
    SigVmdk,
    SigCrx,
    SigWebP,
    SigFh8,
    SigDmg,
    SigCwk5v0,
    SigCwk5v1,
    SigCwk5v2,
    SigCwk6v0,
    SigCwk6v1,
    SigCwk6v2,
    SigToast0,
    SigToast1,
    Sig3gp,
    Sig3gp2,
    SigOar,
    SigTox,
    SigMlv,
    SigUbdc0,
    SigUbdc1,
    SigLz4,
    SigCab,
    SigFlif,
    SigStg,
    SigDjvu,
    SigDjv,
    SigXml0,
    SigXml1,
    SigXml2,
    SigXml3,
    SigXml4,
    SigXml5,
    SigWoff,
    SigWoff2,
    SigDer,
    SigDcm,
    SigLep,
    SigUBoot,
    SigDat,
    SigNes,
    Sig7z,
    SigTarGz,
    SigTarXz,
    SigTarZLzw,
    SigTarZLzh,
    SigTar0,
    SigTar1,
    SigMkv,
    SigMka,
    SigMks,
    SigMk3d,
    SigWebm,
    SigWasm,
    SigSwfCws,
    SigSwfFws,
    SigDeb,
    SigRtf,
    SigMpegP,
    SigMpgP,
    SigVob,
    SigM2p,
    SigMpeg,
    SigMpg,
    SigMp4,
    SigZlib0,
    SigZlib1,
    SigZlib2,
    SigZlib3,
    SigZlib4,
    SigZlib5,
    SigZlib6,
    SigZlib7,
    SigLzfse,
    SigOrc,
    SigAvro,
    SigRc,
    SigLuac,
    SigPyc,
    SigAlias,
    SigEml,
    SigPgp,
    SigVpk,
    SigAff,
    SigJpg0,
    SigJpg1,
    SigJpg2,
    SigJpg3,
    SigJpeg0,
    SigJpeg1,
    SigJpeg2,
    SigJpeg3,
    SigXcf,
    SigFlv,
    SigDatWinReg,
    SigTxtUtf8,
    SigTxtUtf16Le,
    SigTxtUtf16Be,
    SigTxtUtf32Le,
    SigTxtUtf32Be,
    SigTxtScsu,
    SigTxtUtf7,
    SigUtfEbcdic,
    SigPostScript,
    SigChm,
    SigSdi,
    SigTape,
    SigAvi,
    SigIlbm,
    SigLbm,
    SigIbm,
    SigIff,
    Sig8svx,
    Sig8sv,
    SigSvx,
    SigSnd,
    Sig8svIff,
    SigAsf,
    SigWma,
    SigWmv,
    SigWav
  ]
