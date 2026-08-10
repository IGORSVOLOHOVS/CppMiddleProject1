# cpp-middle-project-sprint-1 <!-- omit in toc -->

- [Начало работы](#начало-работы)
- [Сборка проекта и запуск тестов](#сборка-проекта-и-запуск-тестов)
  - [Команды для сборки проекта](#команды-для-сборки-проекта)
  - [Команды для запуска приложения](#команды-для-запуска-приложения)
  - [Команда для запуска тестов](#команда-для-запуска-тестов)
  - [Команды для запуска отладчика](#команды-для-запуска-отладчика)
- [Сборка под Windows](#сборка-под-windows)
  - [Что нужно установить](#что-нужно-установить)
  - [Как собрать](#как-собрать)
  - [Пресеты CMake](#пресеты-cmake)


Шаблон репозитория для практического задания 1-го спринта «Мидл разработчик С++»

## Начало работы

1. Нажмите зелёную кнопку `Use this template`, затем `Create a new repository`.
2. Назовите свой репозиторий.
3. Склонируйте созданный репозиторий командой `git clone your-repository-name`.
4. Создайте новую ветку командой `git switch -c development`.
5. Откройте проект в `Visual Studio Code`.
6. Нажмите `F1` и откройте проект в dev-контейнере командой `Dev Containers: Reopen in Container`.

## Сборка проекта и запуск тестов

Данный репозиторий использует два инструмента:

- **Conan** — свободный менеджер пакетов для C и C++ с открытым исходным кодом (MIT). Позволяет настраивать процесс сборки программ, скачивать и устанавливать сторонние зависимости и необходимые инструменты. Подробнее о Conan:
  - https://habr.com/ru/articles/884464
  - https://docs.conan.io/2.0/tutorial/consuming_packages/build_simple_cmake_project.html
  - https://docs.conan.io/2.0/tutorial/consuming_packages/the_flexibility_of_conanfile_py.html
- **cmake** — генератор систем сборки для C и C++. Позволяет создавать проекты, которые могут компилироваться на различных платформах и с различными компиляторами. Подробнее о cmake:
  - https://dzen.ru/a/ZzZGUm-4o0u-IQlb
  - https://neerc.ifmo.ru/wiki/index.php?title=CMake_Tutorial
  - https://cmake.org/cmake/help/book/mastering-cmake/cmake/Help/guide/tutorial/index.html

### Команды для сборки проекта

```bash
mkdir build ; cd build

# Вызывается один раз перед сборкой проекта, чтобы скачать и установить все необходимые зависимости
conan install --settings=build_type=Debug --build=missing ..

# Вызывается каждый раз, когда необходимо собрать проект
conan build --settings=build_type=Debug ..
```

### Команды для запуска приложения

```bash
echo "Hello OpenSSL crypto world!" > input.txt

./CryptoGuard -i input.txt     -o encrypted.txt -p 1234 --command encrypt
./CryptoGuard -i encrypted.txt -o decrypted.txt -p 1234 --command decrypt

./CryptoGuard -i input.txt     --command checksum
./CryptoGuard -i decrypted.txt --command checksum
```

### Команда для запуска тестов

```bash
cd build
ctest
```

### Команды для запуска отладчика

В `Visual Studio Code` настройки параметров для запуска отладчика находятся в `.vscode/launch.json` файле. Поскольку в этом файле уже есть одна конфигурация `Launch CryptoGuard` для запуска приложения, которое вычисляет контрольную сумму файла, то для запуска отладчика достаточно нажать `F5` или открыть окно `Run and Debug` комбинацией клавиш `Ctrl+Shift+D`.

## Сборка под Windows

Dev-контейнер остаётся основным способом сборки, но проект собирается и нативно —
компилятором MSVC, без Docker и без WSL. Точка входа одна: `scripts\build_windows.ps1`.

### Что нужно установить

- **Visual Studio 2022** (Community достаточно) с рабочей нагрузкой
  «Разработка классических приложений на C++». Нужен компилятор MSVC v143;
  проверялось на `cl.exe` 19.44. Более ранние версии могут не потянуть C++23:
  проект опирается на `std::print` и `std::format`.
- **CMake ≥ 3.30** и **Ninja** на `PATH`. Оба приезжают вместе с компонентом
  Visual Studio «C++ CMake tools for Windows», если ставить их отдельно не хочется.
- **Conan 2** (`pip install conan`) — из него берутся OpenSSL, Boost и GTest,
  ровно как в контейнере. Профиль `default` скрипт создаёт сам, если его ещё нет.

Отдельно запускать «Developer Command Prompt» не требуется — скрипт сам находит
`vcvars64.bat` (через `vswhere`, с запасными путями) и вносит окружение MSVC в
свой процесс.

### Как собрать

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
```

Скрипт ставит зависимости через Conan, настраивает CMake, собирает всё и прогоняет
`ctest`, а в конце печатает пути к получившимся `.exe`. Результат лежит в
`build\windows`, основной исполняемый файл — `build\windows\CryptoGuard.exe`:

```powershell
"Hello OpenSSL crypto world!" | Out-File -Encoding ascii -NoNewline input.txt

build\windows\CryptoGuard.exe -i input.txt     -o encrypted.txt -p 1234 --command encrypt
build\windows\CryptoGuard.exe -i encrypted.txt -o decrypted.txt -p 1234 --command decrypt
build\windows\CryptoGuard.exe -i decrypted.txt --command checksum
```

Полезные ключи:

| Ключ | Зачем |
| --- | --- |
| `-BuildType Debug` | сборка с отладочной информацией в `build\windows-debug` |
| `-Clean` | удалить каталог сборки и собрать с нуля |
| `-SkipTests` | не запускать `ctest` |

Про `-BuildType Debug` стоит знать заранее: готовых Debug-бинарников OpenSSL,
Boost и GTest для MSVC в conan-center нет, поэтому первый такой запуск соберёт
их из исходников — это часы, а не минуты. Release ставится из кеша conan-center
за считанные секунды.

### Пресеты CMake

`CMakePresets.json` описывает обе платформы, поэтому IDE (Visual Studio, VS Code,
CLion) подхватывает конфигурацию сама:

| Пресет | Платформа | Генератор | Каталог сборки |
| --- | --- | --- | --- |
| `linux-default` | Linux / dev-контейнер | Unix Makefiles | `build/` |
| `windows-msvc-release` | Windows, MSVC x64 | Ninja | `build/windows/` |
| `windows-msvc-debug` | Windows, MSVC x64 | Ninja | `build/windows-debug/` |

Каждый пресет ждёт рядом `conan_toolchain.cmake`, который генерирует `conan install`,
поэтому запускать их вручную нужно после Conan:

```powershell
# Linux
conan install . --build=missing -s build_type=Debug
cmake --preset linux-default && cmake --build --preset linux-default

# Windows, из «Developer PowerShell for VS 2022»
conan install . --output-folder build\windows --build=missing -s build_type=Release -c tools.cmake.cmaketoolchain:generator=Ninja
cmake --preset windows-msvc-release
cmake --build --preset windows-msvc-release
```

Windows-пресеты рассчитаны на окружение MSVC: если запускать их руками, а не
через `scripts\build_windows.ps1`, делать это надо из «Developer PowerShell for
VS 2022», иначе CMake не найдёт `cl.exe`.
