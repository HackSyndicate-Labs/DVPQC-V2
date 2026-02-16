@echo off
echo [*] Compiling Lab 6 - Entropy Collapse (Hardcore Edition)...

:: Attempt to setup VS environment
if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
) else (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
        call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    ) else (
        if exist "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat" (
            call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
        )
    )
)

set PQCLEAN=..\external\pqclean
set COMMON=%PQCLEAN%\common
set KEM=%PQCLEAN%\crypto_kem\ml-kem-768\clean

:: Common Sources
set COMMON_SRCS=%COMMON%\fips202.c %COMMON%\sha2.c %COMMON%\sp800-185.c %COMMON%\nistseedexpander.c %COMMON%\aes.c

:: KEM Sources (Listed explicitly for MSVC)
set KEM_SRCS=%KEM%\cbd.c %KEM%\indcpa.c %KEM%\kem.c %KEM%\ntt.c %KEM%\poly.c %KEM%\polyvec.c %KEM%\reduce.c %KEM%\symmetric-shake.c %KEM%\verify.c

:: Lab Sources
set LAB_SRCS=src\main.cpp src\Utils\EntropyPool.cpp src\Crypto\KyberManager.cpp src\Radio\Transceiver.cpp

:: Use CL (MSVC) instead of G++ if G++ is missing but CL is present
where cl >nul 2>nul
if %errorlevel% equ 0 (
    echo [+] MSVC Compiler found.
    cl /O2 /EHsc /std:c++17 ^
       /Iinclude ^
       /I%COMMON% ^
       /I%KEM% ^
       %LAB_SRCS% ^
       %COMMON_SRCS% ^
       %KEM_SRCS% ^
       /Felab6.exe
) else (
    echo [-] MSVC not found or setup failed. Trying G++...
    g++ -O3 -Wall -std=c++17 ^
        -Iinclude ^
        -I%COMMON% ^
        -I%KEM% ^
        %LAB_SRCS% ^
        %COMMON_SRCS% ^
        %KEM_SRCS% ^
        -o lab6.exe
)

if %errorlevel% neq 0 (
    echo [!] Compilation failed!
    exit /b %errorlevel%
)

echo [+] Compilation successful!
echo [*] Running Lab 6...
lab6.exe
