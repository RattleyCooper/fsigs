# fsigs

Library for validating files based on their file signature.  [File signatures are listed here](https://en.wikipedia.org/wiki/List_of_file_signatures).  If a file signature is missing, create a pull request or open an issue explaining which file signature you'd like added.  If it's not on the list from wikipedia then provide as much detail about how you obtained the file signature.

## Example

```nim
import fsigs/[fsigs, signatures]


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
  if f.matches(fileSig):
    echo fileSig.name

echo f.matchesAny(fileSigs)

f.close()

```
