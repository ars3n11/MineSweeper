REM Usage: script.bat target_PID donor_PID module_name
@ECHO off
ECHO ==========================1==============================
ECHO MineSweeper.exe /l
MineSweeper.exe /l
ECHO ==========================2==============================
ECHO MineSweeper.exe /l /t:%1
MineSweeper.exe /l /t:%1
ECHO ==========================3==============================
ECHO MineSweeper.exe /s
MineSweeper.exe /s
ECHO ==========================4==============================
ECHO MineSweeper.exe /s /t:%1
MineSweeper.exe /s /t:%1
ECHO ==========================5==============================
ECHO MineSweeper.exe /s /t:%1 /m:%3
MineSweeper.exe /s /t:%1 /m:%3
ECHO ==========================6==============================
ECHO MineSweeper.exe /u
MineSweeper.exe /u
ECHO ==========================7==============================
ECHO MineSweeper.exe /c /u /t:%1
MineSweeper.exe /c /u /t:%1
ECHO ==========================8==============================
ECHO MineSweeper.exe /c /r /t:%1 /d:%2
MineSweeper.exe /c /r /t:%1 /d:%2
ECHO ==========================9==============================
ECHO MineSweeper.exe /s /t:%1 /v
MineSweeper.exe /s /t:%1 /v