@echo off
setlocal EnableExtensions
set "ROOT=%~dp0.."
cd /d "%ROOT%"
if exist native\threefish_candidate.dll del /q native\threefish_candidate.dll
where cl >nul 2>nul
if errorlevel 1 (
  echo ERROR: MSVC cl.exe was not found on PATH.
  exit /b 1
)
cl /nologo /O2 /LD /W3 native\threefish1024.c /Fe:native\threefish_candidate.dll
if errorlevel 1 goto :fail
if exist native\threefish_native.dll del /q native\threefish_native.dll
copy /y native\threefish_candidate.dll native\threefish_native.dll >nul
if errorlevel 1 goto :fail
python -m venv .venv
if errorlevel 1 goto :fail
call .venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 goto :fail
set PYTHONPATH=%ROOT%\src;%ROOT%\experimental\witness-v6
.venv\Scripts\python.exe -m pytest -q
if errorlevel 1 goto :fail
del /q native\threefish_candidate.dll 2>nul
del /q native\threefish_native.dll 2>nul
echo Windows installation and regression tests completed.
exit /b 0

:fail
del /q native\threefish_candidate.dll 2>nul
del /q native\threefish_native.dll 2>nul
exit /b 1
