@echo off
rem Analyst Lab friend-package VM test: removes Sysmon from the lab VM first (asks for admin).
rem Only inside the lab VM; undone by restoring the 'clean' snapshot.
powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"%~dp0vm_remove_sysmon.ps1\"'"
