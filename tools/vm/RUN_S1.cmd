@echo off
rem Analyst Lab scenario S1 "download and run" (harmless): double-click inside the VM.
rem No administrator rights needed. Talks only to the lab's test server on the laptop.
powershell -NoProfile -ExecutionPolicy Bypass -NoExit -File "%~dp0run_scenario.ps1" -Scenario s1
