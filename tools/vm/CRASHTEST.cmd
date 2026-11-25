@echo off
rem Analyst Lab agent crash-restart test: double-click inside the VM (asks for administrator rights once).
rem Kills the agent, waits for Task Scheduler to restart it, sends the times to the laptop.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','%~dp0lab\tools\vm_crash_test.ps1'"
