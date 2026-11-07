# cpp-middle-project1

CryptoGuard: a console tool in C++23 that encrypts and decrypts a file with AES-256-CBC under a password, and prints a file's SHA-256 checksum. It was written for the first sprint of the Yandex Practicum "Middle C++ developer" course, and OpenSSL does the cryptography.

```powershell
CryptoGuard.exe -i input.txt     -o encrypted.txt -p 1234 --command encrypt
CryptoGuard.exe -i encrypted.txt -o decrypted.txt -p 1234 --command decrypt
CryptoGuard.exe -i decrypted.txt --command checksum
```

Errors in the core travel as `std::expected`: `crypto_guard_ctx.h` and `crypto_guard_ctx.cpp` hold no exception and no lock, and `.\recipe.ps1 test` fails if one appears. The command line beside them keeps its exceptions, because Boost.Program_options reports by throwing.

## Layout

```text
include/   crypto_guard_ctx.h, the core; cmd_options.h, the command line
src/       their sources, and main.cpp
tests/     GoogleTest cases, and the check of the manual list
scripts/   build_windows.ps1, the MSVC build through Conan
```

## Build and test

`.\recipe.ps1 test` builds the tool, runs `ctest`, `clang-tidy` and `clang-format`, and searches the core for locks and for `throw`, `try` and `catch`. It needs mingw g++ with the OpenSSL it carries, cmake, ninja and LLVM. `docs/install.md` has the details, and `docs/manual.md` covers the commands.

The source is MIT licensed under the copyright that `LICENSE` names.
