OutFile "D:\Shaneen\installer_output\ShaheenInstaller.exe"
InstallDir "\Shaheen"
RequestExecutionLevel admin
Page directory
Page instfiles

Section "Install"
  SetOutPath 
  File /r "D:\Shaneen\dist\Shaheen\*.*"
  CreateShortCut "\Shaheen.lnk" "\Shaheen.exe"
  CreateShortCut "\Shaheen\Shaheen.lnk" "\Shaheen.exe"
SectionEnd
