# CryptoGuard: software requirements specification

Reverse-engineered from the code at commit `598c511` on 2026-11-18. It states what
the code does, not what it should do. Every requirement names its source; where the
code does not answer, the question is in section 9. The documentation hub is
[`docs/README.md`](docs/README.md).

<!-- jira-sync:start -->
Jira: KAN-107

## Tasks

This list is one ticket in Jira project KAN, [KAN-107](https://igorsvolohovs.atlassian.net/browse/KAN-107). Each line is a checkbox there: tick it in Jira and the sync ticks it here; add a checkbox there and it is appended here. Done items are the features described in section 3; open items are what the project declares but the code does not do yet.

- [x] Command line (section 3.1) <!-- spec-command-line -->
- [x] Program (section 3.2) <!-- spec-program -->
- [x] Core (section 3.3) <!-- spec-core -->
- [ ] An installer: (declared, not implemented) <!-- spec-an-installer -->
- [ ] Eight lab requirements are declared unmet: (declared, not implemented) <!-- spec-eight-lab-requirements-are-declared-unmet -->
- [ ] Manual tests: (declared, not implemented) <!-- spec-manual-tests -->

<!-- jira-sync:end -->

## 1. Purpose and scope

CryptoGuard is a console program that encrypts and decrypts a file with AES-256-CBC
under a password and computes the SHA-256 checksum of a file (`README.md:3`).

In scope:

- the command-line parser `ProgramOptions` (`include/cmd_options.h`, `src/cmd_options.cpp`);
- the core `CryptoGuardCtx` (`include/crypto_guard_ctx.h`, `src/crypto_guard_ctx.cpp`);
- the entry point `src/main.cpp`;
- the build definition (`CMakeLists.txt`, `CMakePresets.json`, `conanfile.py`) and the tests.

Out of scope: an installer (`docs/install.md:3`); protection of secrets that matter
(`docs/manual.md:17`); key management, file formats with headers, authenticated
encryption (none is present in the code); the lab tooling, which is specified by
repo-quality-template.

## 2. Context

| Item | Description | Source |
| --- | --- | --- |
| Actor | a person at a console who runs `CryptoGuard.exe` with options | `README.md:5-9` |
| Actor | C++ code that links `CryptoGuard_imp` and calls `CryptoGuardCtx` | `CMakeLists.txt:62-76`, `docs/manual.md:21-30` |
| External library | OpenSSL EVP (cipher, key derivation, digest, error queue) | `src/crypto_guard_ctx.cpp:10-12` |
| External library | Boost.Program_options | `include/cmd_options.h:4` |
| Runtime | Windows with mingw g++ (gate route), Windows with MSVC, Linux dev container with g++-14 | `docs/install.md`, `.devcontainer/Dockerfile:7` |
| File system | the input file is read and the output file written; nothing else is stored | `src/main.cpp:11-21` |

## 3. Functional requirements

### 3.1 Command line

- **FR-1.** The system shall accept the options `-c/--command`, `-i/--input`,
  `-o/--output`, `-p/--password` with a string value and `-h/--help` without one.
  Source: `src/cmd_options.cpp:13-17`. Verification: `Parse_Aliases_True`, `Parse_AliasesMix_True`.
- **FR-2.** The system shall print the option list and fail with `No arguments!` when
  started with no arguments. Source: `src/cmd_options.cpp:23-26`. Verification: `Parse_NoOptions_Exception`.
- **FR-3.** The system shall print the option list and fail when `--help` is present,
  with or without other options. Source: `src/cmd_options.cpp:40-43`.
  Verification: `Parse_Help_Exception`, `Parse_HelpAndOtherArg_Exception`.
- **FR-4.** The system shall print the option list and fail with `Parsingrror: <reason>`
  when Boost cannot parse the command line (missing value, repeated option, unknown option).
  Source: `src/cmd_options.cpp:31-36`. Verification: `Parse_EmptyInput_Exception`,
  `Parse_EmptyOutput_Exception`, `Parse_EmptyPassword_Exception`, `Parse_DoubleArgInit_Exception`.
- **FR-5.** The system shall require `--input` and `--command` for every command.
  Source: `src/cmd_options.cpp:45-47`. Verification: `Parse_CheckSumOutputPassword_Exception`.
- **FR-6.** The system shall accept only `encrypt`, `decrypt` and `checksum` as the
  command and fail with `Invalid command: <value>` otherwise. Source: `include/cmd_options.h:32-36`,
  `src/cmd_options.cpp:49-54`. Verification: `ParseGetCommand_UnknownCommand_Exception`,
  `ParseGetCommand_CommandEncrypt_True`, `ParseGetCommand_CommandDecrypt_True`, `ParseGetCommand_CommandCheckSum_True`.
- **FR-7.** The system shall require `--password` and `--output` for `encrypt` and `decrypt`.
  Source: `src/cmd_options.cpp:58-66`. Verification: no test (the tests that omit a value
  fail earlier, under FR-4).
- **FR-8.** The system shall accept and ignore `--output` and `--password` for `checksum`.
  Source: `src/cmd_options.cpp:68-70`. Verification: `ParseGetCommand_CommandCheckSum_True`.

### 3.2 Program

- **FR-9.** The system shall refuse to run when the input and output path strings are
  equal. Source: `src/main.cpp:34-36`. Verification: no test.
- **FR-10.** The system shall open the input and output files in binary mode and fail
  with `Open file error: <path>` when a file cannot be opened. Source: `src/main.cpp:11-21`.
  Verification: no test.
- **FR-11.** The system shall print one success line to stdout after each command, and
  for `checksum` the line `Result: <checksum>`. Source: `src/main.cpp:48-49`, `:60-61`, `:73-74`.
  Verification: no test.
- **FR-12.** The system shall print `Error: <message>` to stderr and exit with code 1 on
  any failure, and exit with code 0 otherwise. Source: `src/main.cpp:82-87`. Verification: no test.

### 3.3 Core

- **FR-13.** The system shall encrypt an input stream into an output stream with
  AES-256-CBC (`EVP_aes_256_cbc`). Source: `src/crypto_guard_ctx.cpp:49-52`, `:102`, `:109-154`.
  Verification: `EncryptDecrypt_HelloOpenSSL_Correct`.
- **FR-14.** The system shall derive the 32-byte key and 16-byte IV from the password with
  `EVP_BytesToKey`, SHA-256, a fixed 8-byte salt and one iteration. Source:
  `src/crypto_guard_ctx.cpp:99-106`, `:163-176`. Verification: no direct test; the round trip in FR-15 depends on it.
- **FR-15.** The system shall decrypt a stream encrypted under the same password back to
  the original bytes. Source: `src/crypto_guard_ctx.cpp:53-56`, `:109-154`.
  Verification: `EncryptDecrypt_HelloOpenSSL_Correct`, `CheckSum_EncryptDecript_Correct`.
- **FR-16.** The system shall read the input in chunks of `CRIPT_BLOCK_SIZE` (1024) bytes and
  write each transformed chunk before reading the next. Source: `include/crypto_guard_ctx.h:13`,
  `src/crypto_guard_ctx.cpp:117-146`. Verification: no test (all test inputs are shorter than 1024 bytes).
- **FR-17.** The system shall return a `CryptoError` of kind `OpenSsl`, with the failing
  call and OpenSSL's reason in the message, when an OpenSSL call fails, including a wrong
  password (when the final-block check catches it, see section 9) and an empty or malformed ciphertext. Source: `src/crypto_guard_ctx.cpp:26-30`,
  `:127-149`. Verification: `EncryptDecrypt_HelloOpenSSLWrongPassword_Error`, `Decrypt_EmptyText_Error`,
  `Decrypt_EmptyPassword_Error`, `Decrypt_ImputIsEqualOutput_Error`.
- **FR-18.** The system shall return a `CryptoError` of kind `Stream` when the input or
  output stream is in a failed state at the start or during reading, or a write fails.
  Source: `src/crypto_guard_ctx.cpp:111-113`, `:132-134`, `:142-152`, `:156-161`.
  Verification: `Encrypt_InvalidInput_Error`, `Encrypt_InvalidOutput_Error`, `Decrypt_InvalidInput_Error`,
  `Decrypt_InvalidOutput_Error`, `Encrypt_ImputIsEqualOutput_Error`.
- **FR-19.** The system shall compute the SHA-256 digest of a stream and return it as a
  lowercase hexadecimal string. Source: `src/crypto_guard_ctx.cpp:57-96`. Verification:
  `CheckSum_HelloOpenSSL_Correct`.
- **FR-20.** The system shall return a `Stream` error from the checksum when the input
  stream is in a failed state. Source: `src/crypto_guard_ctx.cpp:58-60`, `:74-77`.
  Verification: `CheckSum_InvalidInput_Error`.

### 3.4 Declared but not implemented

- An installer: `.\recipe.ps1 install` prints `nothing to install`; "there is no
  installer yet" (`docs/install.md:13`, `recipe.ps1:80`).
- Eight lab requirements are declared unmet: R-02, R-09, R-12, R-13, R-14, R-37, R-41,
  R-42, tracked as issues #8-#15 (`README.md:30`).
- Manual tests: the list exists but holds none (`tests/manual/tests.json`, `docs/manual.md:36`).
  `docs/manual.md:36` gives the reason as "every behaviour the tool has is checked by a script",
  but FR-9..FR-12 (`src/main.cpp`) have no test.

## 4. Interfaces

### 4.1 Command line

| Option | Value | Required for | Source |
| --- | --- | --- | --- |
| `-c`, `--command` | `encrypt`, `decrypt`, `checksum` | all | `src/cmd_options.cpp:13-14`, `:45-54` |
| `-i`, `--input` | path | all | `src/cmd_options.cpp:15`, `:45` |
| `-o`, `--output` | path | `encrypt`, `decrypt` | `src/cmd_options.cpp:16`, `:60` |
| `-p`, `--password` | string | `encrypt`, `decrypt` | `src/cmd_options.cpp:17`, `:60` |
| `-h`, `--help` | none | - | `src/cmd_options.cpp:13`, `:40-43` |

| Output | Channel | Source |
| --- | --- | --- |
| `Input file <in> was encrypted successfuly in output file <out>.` | stdout, exit 0 | `src/main.cpp:48` |
| `Input file <in> was decrypted successfuly in output file <out>.` | stdout, exit 0 | `src/main.cpp:60` |
| `Check sum of input file <in> was calculated successfuly.` and `Result: <hex>` | stdout, exit 0 | `src/main.cpp:73` |
| option list | stdout, on FR-2, FR-3, FR-4 | `src/cmd_options.cpp:24`, `:34`, `:41` |
| `Error: <message>` | stderr, exit 1 | `src/main.cpp:83-84` |

### 4.2 C++ API (`namespace CryptoGuard`)

| Item | Signature or value | Source |
| --- | --- | --- |
| `CryptoGuardCtx::EncryptFile` | `std::expected<void, CryptoError>(std::iostream &in, std::iostream &out, std::string_view password)`, `[[nodiscard]]` | `include/crypto_guard_ctx.h:39-40` |
| `CryptoGuardCtx::DecryptFile` | same signature | `include/crypto_guard_ctx.h:41-42` |
| `CryptoGuardCtx::CalculateChecksum` | `std::expected<std::string, CryptoError>(std::iostream &in)` | `include/crypto_guard_ctx.h:43` |
| copy / move | copy deleted, move defaulted `noexcept` | `include/crypto_guard_ctx.h:32-36` |
| `CryptoError` | `{ CryptoErrorKind kind; std::string message; }` | `include/crypto_guard_ctx.h:21-24` |
| `CryptoErrorKind` | `Stream`, `OpenSsl` | `include/crypto_guard_ctx.h:16-19` |
| `CRIPT_BLOCK_SIZE`, `ERROR_MSG_SIZE` | 1024, 1024 | `include/crypto_guard_ctx.h:13-14` |
| `ProgramOptions` | `Parse(int, char*[])` throws `std::runtime_error`; `GetCommand`, `GetInputFile`, `GetOutputFile`, `GetPassword` | `include/cmd_options.h:23-28` |

### 4.3 Build interface

| Item | Meaning | Source |
| --- | --- | --- |
| target `CryptoGuard_imp` | static library of all `src/*.cpp` except `main.cpp` | `CMakeLists.txt:62-76` |
| target `CryptoGuard` | the program | `CMakeLists.txt:78-80` |
| target `CryptoGuard_tests` | GoogleTest executable from `tests/*.cpp` | `CMakeLists.txt:82-87` |
| ctest `CryptoGuard_Tests`, `manual_list` | GoogleTest run; pytest over the manual list, only with fetched dependencies | `CMakeLists.txt:89-98` |
| option `CRYPTO_GUARD_FETCH_DEPENDENCIES` | default `OFF`; `ON` fetches Boost and GoogleTest | `CMakeLists.txt:19`, `:33-54` |
| presets | `linux-default`, `windows-msvc-release`, `windows-msvc-debug` | `CMakePresets.json` |

## 5. Data

- Input: any file, read as bytes (`src/main.cpp:16`).
- Encrypted file: the AES-256-CBC output of OpenSSL EVP, with no header, salt or IV
  stored (`src/crypto_guard_ctx.cpp:109-154`). Padding is OpenSSL's default, since
  `EVP_CIPHER_CTX_set_padding` is not called (inference from the absence of the call).
- Checksum: 64 lowercase hexadecimal characters for SHA-256 (`src/crypto_guard_ctx.cpp:90-95`;
  test value `tests/crypo_guard_ctx_test.cpp:107`).
- Manual test list `tests/manual/tests.json`: `{"version": 1, "tests": [...]}`; each entry has
  `id`, `title`, `expected`, `steps`, optional `issue`, `blocking`, `needs`; UTF-8 without BOM
  (`tests/test_manual_list.py:24-49`).
- Nothing persists between runs.

## 6. Non-functional requirements

- **NFR-1.** The two core files shall contain no `throw`, `try`, `catch` and no lock or
  synchronisation primitive; `.\recipe.ps1 test` fails on a hit. Source: `recipe.ps1:22`,
  `:62-71`, `:126-127`; `include/crypto_guard_ctx.h:26`.
- **NFR-2.** The code shall compile as C++23 without compiler extensions. Source: `CMakeLists.txt:4-6`.
- **NFR-3.** With GNU or Clang, warnings shall be errors (`-Wall -Wextra -Wpedantic -Werror`,
  `-Wfatal-errors`). Source: `CMakeLists.txt:9-11`, `:21-25`.
- **NFR-4.** `src/*.cpp` and `tests/*.cpp` shall pass clang-tidy with `clang-diagnostic-*`, `clang-analyzer-*`,
  `bugprone-*`, `performance-*`, `portability-*` as errors. Source: `.clang-tidy`, `recipe.ps1:121`.
- **NFR-5.** Sources shall be formatted by `.clang-format` (LLVM base, 120 columns, indent 4).
  Source: `.clang-format`, `recipe.ps1:124`.
- **NFR-6.** File I/O shall be binary on every platform so that ciphertext is not altered on
  Windows. Source: `src/main.cpp:12-16`.
- **NFR-7.** On the mingw route OpenSSL shall be linked statically, so no OpenSSL DLL is needed
  at run time. Source: `recipe.ps1:55-56`, `CMakeLists.txt:28-31`, `docs/install.md:11`.
- **NFR-8.** Fetched dependencies shall be pinned by URL and SHA-256. Source: `CMakeLists.txt:36-51`.
- **NFR-9.** The tool makes no claim to protect real secrets: the password is a command-line
  argument and the key derivation uses one iteration and a fixed salt. Source: `docs/manual.md:17`,
  `src/crypto_guard_ctx.cpp:165-169`.
- **NFR-10.** The repository follows the lab tooling of repo-quality-template; `README.md:30`
  states compliance with lab requirements revision 4.0.0 with the exceptions in 3.4.

## 7. Constraints and dependencies

| Dependency | Version | Source |
| --- | --- | --- |
| C++ standard | 23 | `CMakeLists.txt:4` |
| CMake | 3.30 or newer (presets file: 3.25) | `CMakeLists.txt:1`, `CMakePresets.json:3-7` |
| OpenSSL | 3.1.1 via Conan; mingw route: whatever the toolchain carries under `opt` | `conanfile.py:12`, `recipe.ps1:56` |
| Boost (program_options) | 1.86.0 | `conanfile.py:13`, `CMakeLists.txt:40` |
| GoogleTest | 1.13.0 | `conanfile.py:14`, `CMakeLists.txt:47` |
| Conan | 2; `cmake/3.30.0` as tool requirement | `docs/install.md:17`, `conanfile.py:15` |
| mingw g++ | 13 or newer | `docs/install.md:7` |
| MSVC | Visual Studio 2022, v143 tools | `scripts/build_windows.ps1:113-116`, `:138-143` |
| Dev container | Ubuntu image by digest, g++-14, clangd-19, Conan profile gcc 14 / gnu23 | `.devcontainer/Dockerfile:3-7`, `.devcontainer/default` |
| Ninja, LLVM (clang-tidy, clang-format), Python with pytest | no version given | `docs/install.md:7`, `CMakeLists.txt:95` |

The code calls `EVP_DigestInit_ex2` and `EVP_MD_free` (`src/crypto_guard_ctx.cpp:70`, `:41`);
inference: these exist from OpenSSL 3.0, so an older OpenSSL will not build it.

## 8. Acceptance

1. `.\recipe.ps1 test` exits with 0: build, `ctest` (`CryptoGuard_Tests` covers FR-1..FR-6, FR-8,
   FR-13, FR-15, FR-17..FR-20, and FR-14 only through the round trip; FR-7 and FR-16 have no test;
   `manual_list`), clang-tidy, clang-format in place, and the NFR-1 search (`recipe.ps1:112-128`).
   The recipe does not fail on a formatting diff; the gates run `git diff --exit-code` after it
   (`.gitea/workflows/propose.yaml:146-148`, `.gitea/workflows/release-gate.yaml:51-53`).
2. FR-9..FR-12 have no automated test. A manual check derived from `src/main.cpp`: run the three
   commands of `README.md:5-9`; the checksums of the input and of `decrypted.txt` match; decrypting
   with another password normally prints `Error: ...` and exits 1 (FR-17); `-i a.txt -o a.txt -p 1234 -c encrypt`
   prints `Error: Names of input and output files are the same: a.txt` (without `-c` and `-p`, the
   parser fails first under FR-5 or FR-7).

## 9. Open questions

- Who uses the tool beyond the course sprint is not stated.
- Why a fixed salt and one iteration were chosen (course requirement or simplification) is not stated.
- Which OpenSSL version the mingw toolchain carries is not recorded in the repository.
- Whether exit code 1 after `--help` (FR-3, FR-12) is intended at the program level; the tests assert
  only that `Parse` throws.
- Whether an empty password should be refused: neither the core nor the parser checks it, and the
  test named `Decrypt_EmptyPassword_Error` fails on a malformed ciphertext instead (see `docs/README.md`, limitation 7).
- How often a wrong password passes the final-block check, given that no MAC is computed (FR-17).
- No performance target, file-size limit or supported platform list is stated.
- Whether the dev-container route still configures with an apt `cmake` against `cmake_minimum_required(VERSION 3.30)`;
  `.devcontainer/devcontainer.json:2` names the image Ubuntu 24.04, and the apt `cmake` version it installs is not recorded.
- Whether the Gitea workflows have run for this repository (`CLAUDE.md`, "Branch protection starts at stage 1").
