#define ReleaseRoot AddBackslash(SourcePath) + ".."
#define DistRoot AddBackslash(ReleaseRoot) + "dist\SHAHEEN"
#define AssetsRoot AddBackslash(ReleaseRoot) + "assets"

[Setup]
AppId={{A7F241B6-2A51-4B74-92E3-5EE35C104A8D}
AppName=SHAHEEN
AppVersion=1.0.0
AppVerName=SHAHEEN Network Traffic Analysis 1.0.0
AppPublisher=SHAHEEN
AppComments=Network Traffic Analysis & Security Monitoring System
DefaultDirName={autopf}\SHAHEEN
DefaultGroupName=SHAHEEN
UninstallDisplayName=SHAHEEN Network Traffic Analysis
UninstallDisplayIcon={app}\SHAHEEN.exe
UsePreviousAppDir=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
SetupIconFile={#AssetsRoot}\SHAHEEN.ico
WizardImageFile={#AssetsRoot}\wizard-banner.bmp
WizardSmallImageFile={#AssetsRoot}\wizard-small.bmp
LicenseFile={#ReleaseRoot}\..\LICENSE
OutputDir={#ReleaseRoot}\installer
OutputBaseFilename=SHAHEEN_Setup_v1.0.0
VersionInfoVersion=1.0.0.0
VersionInfoCompany=SHAHEEN
VersionInfoDescription=Network Traffic Analysis & Security Monitoring System
VersionInfoProductName=SHAHEEN
VersionInfoProductVersion=1.0.0
Compression=lzma2/ultra64
SolidCompression=yes
SetupLogging=yes
Uninstallable=yes
CloseApplications=yes
CloseApplicationsFilter=SHAHEEN.exe

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "npcap"; Description: "Open the official Npcap download page (required for live capture)"; GroupDescription: "Optional:"; Flags: unchecked; Check: not IsNpcapInstalled

[Files]
Source: "{#DistRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ReleaseRoot}\..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "{#AssetsRoot}\shaheen.env.example"; DestDir: "{app}\config"; Flags: ignoreversion

[Icons]
Name: "{group}\SHAHEEN"; Filename: "{app}\SHAHEEN.exe"; WorkingDir: "{app}"
Name: "{autodesktop}\SHAHEEN"; Filename: "{app}\SHAHEEN.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\SHAHEEN.exe"; Description: "Launch SHAHEEN"; WorkingDir: "{app}"; Flags: postinstall nowait skipifsilent
Filename: "https://npcap.com/#download"; Description: "Visit the official Npcap download page"; Flags: shellexec postinstall skipifsilent unchecked; Tasks: npcap; Check: not IsNpcapInstalled

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\Shaheen"; Check: ShouldRemoveUserData

[Code]
var
  RemoveUserData: Boolean;

function IsNpcapInstalled: Boolean;
begin
  Result :=
    RegKeyExists(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\npcap') or
    RegKeyExists(HKEY_LOCAL_MACHINE, 'SYSTEM\CurrentControlSet\Services\npf') or
    FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll')) or
    FileExists(ExpandConstant('{sys}\wpcap.dll'));
end;

function ShouldRemoveUserData: Boolean;
begin
  Result := RemoveUserData;
end;

function InitializeUninstall: Boolean;
begin
  Result := True;
  RemoveUserData := False;
  if DirExists(ExpandConstant('{localappdata}\Shaheen')) then
    RemoveUserData :=
      MsgBox(
        'Remove SHAHEEN databases, configuration, reports, captures, logs, and backups from your user profile?' + #13#10 + #13#10 +
        'Choose No to keep your data for a later reinstall.',
        mbConfirmation,
        MB_YESNO or MB_DEFBUTTON2
      ) = IDYES;
end;
