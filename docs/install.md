# Install

There is no installer: the tool is one executable, built from this repository.

To build and test it here:

1. Install mingw g++ 13 or newer with its OpenSSL under `opt`, CMake 3.30 or newer, Ninja, and LLVM for `clang-tidy` and `clang-format`.
2. Clone this repository.
3. Run `.\recipe.ps1 test`. The first run downloads Boost and GoogleTest, whose archives `CMakeLists.txt` pins by hash.

`recipe.ps1` looks for g++ and OpenSSL in `C:\ProgramData\mingw64\mingw64` and for LLVM in `C:\Program Files\LLVM\bin`, and adds the two `bin` folders to its own PATH. OpenSSL links statically, so the program looks for no OpenSSL DLL.

`.\recipe.ps1 build` compiles `build\CryptoGuard.exe` and its tests. `.\recipe.ps1 install` does nothing: there is no installer yet.

## With Conan and MSVC

`scripts\build_windows.ps1` is the older route: Visual Studio 2022 with the C++ workload, CMake, Ninja and Conan 2. It installs OpenSSL, Boost and GoogleTest through Conan, configures from `CMakePresets.json`, builds into `build\windows` and runs `ctest`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
```

`-BuildType Debug` makes Conan compile the libraries from source, which takes hours. `.devcontainer` is the same route on Linux. No gate builds either of these: the gates take the mingw route only.
