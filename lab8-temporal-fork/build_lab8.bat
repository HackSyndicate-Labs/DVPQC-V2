@echo off
setlocal
echo [BUILD] Setting up MSVC Environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"

echo [BUILD] Compilation Started for Lab 8 (Hardcore)...
mkdir build 2>nul

echo [BUILD] Compiling Security Controller & Modules...
cl /nologo /O2 /I"src" /I"src/hal" /Fe"build/lab8.exe" src/main.c src/core/security_controller.c src/phys/power_profile.c src/math/ntt_accel.c

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Compilation Failed!
    exit /b %ERRORLEVEL%
)

echo [BUILD] Compiling Fuzzing Harness...
cl /nologo /O2 /I"src" /I"src/hal" /Fe"build/lab8_fuzz.exe" fuzz/fuzz_harness.c src/core/security_controller.c src/phys/power_profile.c src/math/ntt_accel.c

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Fuzz Harness Compilation Failed!
    exit /b %ERRORLEVEL%
)

echo [SUCCESS] Build Complete. Artifacts in 'build/' directory.
endlocal
