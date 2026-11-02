[Setup]
AppName=Shaheen
AppVersion=0.1.0
DefaultDirName={pf}\Shaheen
DefaultGroupName=Shaheen
OutputDir=..\installer_output
OutputBaseFilename=ShaheenSetup
Compression=lzma2
SolidCompression=yes

[Files]
Source: "..\dist\Shaheen\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Shaheen"; Filename: "{app}\Shaheen.exe"
Name: "{commondesktop}\Shaheen"; Filename: "{app}\Shaheen.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked
