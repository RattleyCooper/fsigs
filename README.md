# fsigs

fsigs is a nim library made for validating files based on their file signature.  fsigs can check against multiple file signatures very quickly(175+ file signatures in less than 1ms).  File signatures were taken from [this list](https://en.wikipedia.org/wiki/List_of_file_signatures), however I did not implement them all.  If a file signature is missing, create a pull request or open an issue explaining which file signature you'd like added.  If it's not on the list from wikipedia then provide as much detail about how you obtained the file signature.

## Signatures

Signature names are listed in the [`signatures.nim` file](https://github.com/RattleyCooper/fsigs/blob/master/fsigs/signatures.nim).  It's important to note that some file types contain multiple file signatures, so you have to check against all signatures for that file type.

## Installation

`nimble install https://github.com/RattleyCooper/fsigs`

## Example

```nim
# Procs in `fsigs`
# FileSignatures in `signatures`
import fsigs/[fsigs, signatures]

const testSig1 = "\x52\x49\x46\x46\x01\x02\x03\x04\x57\x41\x56\x45"
echo testSig1.matches(SigWav)

const fileSigs = @[
  SigJpeg0,
  SigJpeg1,
  SigJpeg2,
  SigJpeg3
] 

var f: File
if not f.open("some.jpg", fmRead):
  raise newException(OSError, "File could not be opened.")

for fileSig in fileSigs:
  if f.matchesAny(fileSig):
    echo fileSig.id

let sig = f.signature(fileSigs)
echo sig
echo sig == fSigJpeg1
echo f.signature(AllFileSignatures)
echo f.matchesAny(fileSigs)

f.close()

```
