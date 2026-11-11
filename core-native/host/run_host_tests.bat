@echo off
rem Builds and runs the protocol tests on Windows, with no Android SDK involved.
rem
rem The previous build script lived under build/, which .gitignore excludes, so a
rem fresh clone could not run the suite the README told it to run. It lives next
rem to the tests now and is checked in.
rem
rem The compiler is found through vswhere rather than a hard-coded Visual Studio
rem path, so this keeps working across VS versions and editions.
setlocal

rem %~dp0 is core-native\host\ (with a trailing backslash), so two levels up is
rem the repository root.
set ROOT=%~dp0..\..
pushd "%ROOT%"

set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if not exist "%VSWHERE%" (
    echo error: vswhere.exe not found. Install Visual Studio with the C++ workload.
    popd & exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VSDIR=%%i
if "%VSDIR%"=="" (
    echo error: no Visual Studio C++ toolset found.
    popd & exit /b 1
)

if not exist "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" (
    echo error: vcvars64.bat missing under %VSDIR%.
    popd & exit /b 1
)

call "%VSDIR%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo error: could not initialise the MSVC environment.
    popd & exit /b 1
)

if not exist build\host mkdir build\host

cl /nologo /std:c++17 /EHsc /O2 /W3 /utf-8 ^
  /Icore-native\src\main\cpp ^
  /Icore-native\src\main\cpp\third_party\monocypher ^
  core-native\host\tests\test_core.cpp ^
  core-native\src\main\cpp\veil\crypto.cpp ^
  core-native\src\main\cpp\veil\keys.cpp ^
  core-native\src\main\cpp\veil\random.cpp ^
  core-native\src\main\cpp\veil\ratchet.cpp ^
  core-native\src\main\cpp\veil\group.cpp ^
  core-native\src\main\cpp\veil\engine.cpp ^
  core-native\src\main\cpp\third_party\monocypher\monocypher.c ^
  core-native\src\main\cpp\third_party\monocypher\monocypher-ed25519.c ^
  /Fe:build\host\test_core.exe ^
  /Fo:build\host\
if errorlevel 1 (
    echo error: compilation failed.
    popd & exit /b 1
)

build\host\test_core.exe
set RESULT=%errorlevel%
popd
exit /b %RESULT%