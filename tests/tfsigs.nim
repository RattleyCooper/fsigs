import std/[unittest]
import fsigs, signatures


suite "fsigs":
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

  test "File Matching":
    assert fileMatches("test_files/test5.jpg", SigJpeg1)
    assert fileMatches(
      "test_files/cantrbry.tar.gz", 
      SigTarGz
    )
    assert fileMatches(
      "test_files/cantrbry.tar.xz", 
      SigTarXz
    )
    assert fileMatches(
      "test_files/test6.png",
      SigPng
    )
    assert fileMatches(
      "test_files/test6.7z",
      Sig7z
    )

    const fileTypes = @[
      (false, SigJpeg0),
      (true,  SigJpeg1),
      (false, SigJpeg2),
      (false, SigJpeg3)
    ]

    var f: File
    if not f.open("test_files/test5.jpg", fmRead):
      raise newException(OSError, "File could not be opened.")
    
    assert f.matches(SigJpeg0) == false
    assert f.matches(SigJpeg1) == true
    assert f.matches(SigJpeg2) == false
    assert f.matches(SigJpeg3) == false

    for ft in fileTypes:
      assert f.matches(ft[1]) == ft[0]

    f.close()
