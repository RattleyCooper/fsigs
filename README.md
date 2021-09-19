# fsigs

Common file signatures as constants.  Used for [cuttle](https://github.com/RattleyCooper/cuttle).  [File signatures are listed here](https://en.wikipedia.org/wiki/List_of_file_signatures).  If a file signature is missing, create a pull request or open an issue explaining which file signature you'd like added.  If it's not on the list from wikipedia then provide as much detail about how you obtained the file signature.

## Example

```nim
import fsigs/fsigs

const Pdf = SigPdf
```
