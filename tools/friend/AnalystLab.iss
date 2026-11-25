; Analyst Lab friend package (DESIGN 9.2). Built by tools\build_friend_package.ps1:
;   ISCC.exe /DProjectRoot=<project> tools\friend\AnalystLab.iss  ->  build\Setup-AnalystLab.exe
; Installs the bundled AnalystLab.exe (recorder + status window) for all users, then runs
; friend_setup.ps1 (folder permissions, Sysmon, recorder task). Uninstall reverses it and deletes all recordings.

#ifndef ProjectRoot
  #define ProjectRoot ".."
#endif
#define AppVersion "0.1.0"

[Setup]
AppId={{6C1F3B0E-5A7D-4E2B-9C61-3A8F0D2E7B44}
AppName=Analyst Lab
AppVersion={#AppVersion}
AppPublisher=Analyst Lab (student project)
DefaultDirName={autopf}\Analyst Lab
DisableProgramGroupPage=yes
DisableDirPage=yes
PrivilegesRequired=admin
OutputDir={#ProjectRoot}\build
OutputBaseFilename=Setup-AnalystLab
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
InfoBeforeFile={#ProjectRoot}\tools\friend\BEFORE_YOU_INSTALL.txt
UninstallDisplayName=Analyst Lab (student project recorder)
UninstallDisplayIcon={app}\AnalystLab.exe
CloseApplications=yes

; No [Dirs] permissions here: friend_setup.ps1 locks C:\ProgramData\AnalystLab down (only the
; friend may read it, only its control\ subfolder is writable; review 2026-10-19).

[Files]
Source: "{#ProjectRoot}\build\dist\AnalystLab\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "{#ProjectRoot}\tools\friend\friend_setup.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "{#ProjectRoot}\tools\sysmon\sysmon-config.xml"; DestDir: "{app}\setup"; Flags: ignoreversion

[Icons]
Name: "{autodesktop}\Analyst Lab"; Filename: "{app}\AnalystLab.exe"
Name: "{autoprograms}\Analyst Lab"; Filename: "{app}\AnalystLab.exe"

[Run]
Filename: "{app}\AnalystLab.exe"; Parameters: "status --first-run"; Description: "Open Analyst Lab (it runs a quick self-test)"; Flags: postinstall nowait runasoriginaluser skipifsilent

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\setup\friend_setup.ps1"" -AppDir ""{app}"" -DataDir ""{commonappdata}\AnalystLab"" -Remove"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveAnalystLab"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\AnalystLab"
Type: filesandordirs; Name: "{app}\sysmon"
Type: filesandordirs; Name: "{app}\setup"

[Code]
var
  RestartWanted: Boolean;

function SetupScript(Extra: String): Integer;
var
  Code: Integer;
begin
  if not Exec('powershell.exe',
      '-NoProfile -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\setup\friend_setup.ps1') +
      '" -AppDir "' + ExpandConstant('{app}') + '" -DataDir "' + ExpandConstant('{commonappdata}\AnalystLab') + '"' + Extra,
      '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := -1;
  Result := Code;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  { an update: stop the running recorder so its files can be replaced }
  Exec('schtasks.exe', '/End /TN "\AnalystLab\AnalystLab Recorder"', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    WizardForm.StatusLabel.Caption := 'Turning on Sysmon and starting the recorder (this can take a few minutes)...';
    Code := SetupScript('');
    if Code = 3 then
      RestartWanted := True
    else if Code <> 0 then
      SuppressibleMsgBox('Setup could not finish turning on recording (code ' + IntToStr(Code) + ').' + #13#10 +
        'Please send Yousif the file C:\ProgramData\AnalystLab\setup-log.txt (it contains no personal information).',
        mbError, MB_OK, IDOK);
  end;
end;

function NeedRestart(): Boolean;
begin
  Result := RestartWanted;
end;
