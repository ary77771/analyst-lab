@echo off
rem Analyst Lab VM diagnostics: double-click inside the VM (asks for administrator rights once).
rem Collects agent/task/log facts and sends them to the laptop (recordings\vmdiag\).
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','%~dp0lab\tools\vm_diag.ps1'"
