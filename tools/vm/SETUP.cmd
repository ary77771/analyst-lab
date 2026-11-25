@echo off
rem Analyst Lab VM setup: double-click inside the VM (it asks for administrator rights once).
rem Runs lab\tools\vm_guest_setup.ps1 from this virtual CD in an elevated PowerShell window.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','%~dp0lab\tools\vm_guest_setup.ps1'"
