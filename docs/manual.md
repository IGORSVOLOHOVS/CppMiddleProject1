# Manual

## The commands

`.\recipe.ps1 run` builds the tool and hands it any further arguments. The built program is `build\CryptoGuard.exe`.

| option | meaning |
| --- | --- |
| `-c`, `--command` | `encrypt`, `decrypt` or `checksum` |
| `-i`, `--input` | the file to read |
| `-o`, `--output` | the file to write, for `encrypt` and `decrypt` |
| `-p`, `--password` | the password, for `encrypt` and `decrypt` |
| `-h`, `--help` | prints the options |

The input and the output must be different files. A wrong password or a damaged file ends in `Error: ...` and exit code 1, and the output file may then hold a partial result.

The password arrives on the command line, so the shell's history and the process list can show it. The key comes from the password and a fixed salt with one round of `EVP_BytesToKey`, so the tool suits a course exercise and not secrets that matter.

## The core

`CryptoGuard::CryptoGuardCtx` works on streams and answers `std::expected`:

```cpp
#include "crypto_guard_ctx.h"

CryptoGuard::CryptoGuardCtx context;
std::stringstream plain{"Hello"}, secret;
auto encrypted = context.EncryptFile(plain, secret, "1234");
if (!encrypted) { /* encrypted.error().kind and .message say why */ }
```

`CryptoError::kind` is `Stream` for an unusable stream or a failed write, and `OpenSsl` when OpenSSL refuses, which is where a wrong password ends. `CalculateChecksum` answers the hexadecimal SHA-256 of a stream.

## The tests

`ctest --test-dir build` runs the GoogleTest cases and the check of `tests/manual/tests.json`. Every behaviour the tool has is checked by a script, so the manual list is empty.
