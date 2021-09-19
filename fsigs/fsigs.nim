
const
  # Shebang at beginning of file.
  SigShebang* = "\x23\x21"

  # Pcap files
  SigLittlePcap* = "\xD4\xC3\xB2\xA1"
  SigBigPcap* = "\xA1\xB2\xC3\xD4"
  
  # Pcap w/ Nanosecond resolution
  SigNsLittlePcap* = "\x4D\x3C\xB2\xA1"
  SigNsBigPcap* = "\xA1\xB2\x3C\x4D"
  
  # Pcap next gen
  SigPcapNextGeneration* = "\x0A\x0D\x0D\x0A"

  # RedHat Package Manager (RPM) package
  SigRpm* = "\xED\xAB\xEE\xDB"

  # SQLite
  SigSqLite3* = "\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00"

  # Amazon Kindle Update Package
  SigKindleBin* = "\x53\x50\x30\x31"

  # ICO File
  SigIco* = "\x00\x00\x01\x00"

  # 3gp / 3gp2 / offset 4
  SigP3Gp* = "\x66\x74\x79\x70\x33\x67"

  # tar.z
  SigTarZLzw* = "\x1F\x9D"
  SigTarZLzh* = "\x1F\xA0"

  # Amiga backup data file
  SigBac* = "\x42\x41\x43\x4B\x4D\x49\x4B\x45\x44\x49\x53\x4B"

  # Amiga backup index file
  SigIdx* = "\x49\x4E\x44\x58"

  # Bzip2
  SigBz2* = "\x42\x5A\x68"

  # Gif
  SigGif87a* = "\x47\x49\x46\x38\x37\x61"
  SigGif89a* = "\x47\x49\x46\x38\x39\x61"

  # Tiff
  SigTif* = "\x49\x49\x2A\x00"
  SigTiff* = "\x4D\x4D\x00\x2A"

  # Canon RAW
  SigCr2* = "\x49\x49\x2A\x00\x10\x00\x00\x00\x43\x52"

  # Kodak Cineon Image
  SigCin* = "\x80\x2A\x5F\xD7"

  # Zip
  SigZip* = "\x50\x4B\x03\x04"
  SigZipEmpty*  = "\x50\x4B\x05\x06"
  SigZipSpanned* = "\x50\x4B\x07\x08"

  # Exe
  SigExe* = "\x5A\x4D"

  # Dos Mz
  SigExeMz* = "\x4D\x5A"

  # Lzip
  SigLzip* = "\x4C\x5A\x49\x50"

  # Rar 1.5 ^
  SigRar1p5* = "\x52\x61\x72\x21\1A\x07\x00"
  
  # Rar 5.0 ^
  SigRar5p0* = "\x52\x61\x72\x21\1A\x07\x01\x00"

  # Png
  SigPng* = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"

  # PDF
  SigPdf* = "\x25\x50\x44\x46\x2D"

  # Ogg
  SigOgg* = "\x4F\x67\x67\x53"

  # Psd
  SigPsd* = "\x38\x42\x50\x53"

  # Wav | 52 49 46 46 ?? ?? ?? ?? 57 41 56 45
  SigWav* = "\x52\x49\x46\x46\x00\x00\x00\x00\x57\x41\x56\x45"

  # Avi | 52 49 46 46 ?? ?? ?? ?? 41 56 49 20
  SigAvi* = "\x52\x49\x46\x46\x00\x00\x00\x00\x41\x56\x49\x20"

  # Mp3
  SigMp3v0* = "\xFF\xFB"
  SigMp3v1* = "\xFF\xF3"
  SigMp3v2* = "\xFF\xF2"
  SigMp3v3* = "\x49\x44\x33"  # w/ Id3 container

  # Bmp
  SigBmp* = "\x42\x4D"

  # ISO
  SigIso* = "\x43\x44\x30\x30\x31"

  # FLAC
  SigFlac* = "\x66\x4C\x61\x43"

  # MIDI
  SigMidi* = "\x4D\x54\x68\x64"

  # Doc, Xls, Ppt, Msg
  SigDoc* = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

  # Dalvik Executable
  SigDalvik* = "\x64\x65\x78\x0A\x30\x33\x35\x00"

  # VMDK
  SigVmdk* = "\x4B\x44\x4D"

  # Crx
  SigCrx* = "\x43\x72\x32\x34"

  # Freehand 8
  SigFh8* = "\x41\x47\x44\x33"

  # Appleworks

  # Apple Disk Image | DMG
  SigDmg* = "\x6B\x6F\x6C\x79"

  # Dat
  SigDat* = "\x50\x4D\x4F\x43\x43\x4D\x4F\x43"

  # Nes Rom
  SigNes* = "\x4E\x45\x53\x1A"

  # 7z
  Sig7z* = "\x37\x7A\xBC\xAF\x27\x1C"

  # Tar.gz
  SigTarGz* = "\x1F\x8B"
  # Tar.xz
  SigTarXz* = "\xFD\x37\x7A\x58\x5A\x00"

  SigMkv* = "\x1A\x45\xDF\xA3"
  SigWebm* = SigMkv

  SigWasm* = "\x00\x61\x73\x6D"
  SigSwfCws* = "\x43\x57\x53"
  SigSwfFws* = "\x46\x57\x53"
  SigDeb* = "\x21\x3C\x61\x72\x63\x68\x3E\x0A"
  SigRtf* = "\x7B\x5C\x72\x74\x66\x31"
  SigMpegv0* = "\x00\x00\x01\xBA"
  SigMpgv0* = SigMpegv0
  SigMp4* = "\x66\x74\x79\x70\x69\x73\x6F\x6D"

  SigXcf* = "\x67\x69\x6D\x70\x20\x78\x63\x66"
  SigFlv* = "\x46\x4C\x56"
  SigDatWinReg* = "\x72\x65\x67\x66"
