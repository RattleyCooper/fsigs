import std/[unittest, times]
import fsigs, signatures


suite "fsigs":
  let t1 = now()
  test "String Matching":
    # Wave is \x52\x49\x46\x46 ?? ?? ?? ?? \x57\x41\x56\x45 where ??
    # denotes a character that can equate to anything.

    # Should match
    const testSig1 = "\x52\x49\x46\x46\x01\x02\x03\x04\x57\x41\x56\x45"
    const testSig2 = "\x52\x49\x46\x46\x02\x03\x04\x05\x57\x41\x56\x45"
    
    # Shouldn't match
    const testSig3 = "\x00\x49\x46\x46\x01\x02\x03\x04\x57\x41\x56\x45"
    const testSig4 = "\x52\x49\x46\x46\x01\x02\x03\x04\x57\x41\x56\x00"
    assert testSig1.matches(SigWav) == true
    assert testSig2.matches(SigWav) == true
    assert testSig3.matches(SigWav) == false
    assert testSig4.matches(SigWav) == false

  echo "    " & $(now() - t1)
  echo ""
  let t2 = now()
  test "Filepath Matching":
    assert fileMatches("tests/test_files/some.jpg", SigJpeg1)
    
    const tarGzFilepath = "tests/test_files/some.tar.gz"
    assert fileMatches(tarGzFilepath, SigTarGz)
    assert fileMatches(tarGzFilepath, SigTarXz) == false

    assert fileMatches(
      "tests/test_files/some.png",
      SigPng
    )
    assert fileMatches(
      "tests/test_files/test.7z",
      Sig7z
    )

  echo "    " & $(now() - t2)
  echo ""
  let t3 = now()
  test "File Matching":
    const fileSigs = @[
      SigJpg0,
      SigJpg1,
      SigJpg2,
      SigJpg3
    ]

    const nSigs = @[
      SigPng, SigTarGz, SigMkv
    ]

    var f: File
    if not f.open("tests/test_files/some.jpg", fmRead):
      raise newException(OSError, "File could not be opened.")
    
    assert f.matches(SigJpeg0) == false
    assert f.matches(SigJpeg1) == true
    assert f.matches(SigJpg1) == true
    assert f.matches(SigJpeg2) == false
    assert f.matches(SigJpeg3) == false

    # Which signature does the file match
    assert f.signature(fileSigs) == fSigJpg1
    assert f.signature(nSigs) == fSigUnknown

    # Does file match any signature in sequence of file signatures
    assert f.matchesAny(fileSigs)
    assert f.matchesAny(nSigs) == false
    f.close()
  
  echo "    " & $(now() - t3)
  echo ""
  let t4 = now()
  test "Signature":
    var f: File
    if not f.open("tests/test_files/some.wav", fmRead):
      raise newException(OSError, "File could not be opened.")
    assert f.signature(AllFileSignatures) == fSigWav
    f.close()
  echo "    " & $(now() - t4)
  echo ""

