@echo off
echo Building LuaJIT...

REM Try to auto-setup Visual Studio environment
if not defined INCLUDE (
    echo Setting up Visual Studio environment...
    
    REM Try VS2022 first
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    ) else if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
    ) else (
        echo Error: Could not find Visual Studio 2022 installation
        echo Please install Visual Studio 2022 or run from Developer Command Prompt
        goto :END
    )
)

REM Verify environment is now set up
if not defined INCLUDE (
    echo Error: Failed to set up Visual Studio environment
    echo Please run this from a Visual Studio Developer Command Prompt
    goto :END
)

pushd vendor\LuaJIT\src

REM Run the MSVC build script for static library
call msvcbuild.bat static

echo We are done here


popd
:END
pause
