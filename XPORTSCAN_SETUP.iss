;This is the setup file for Inno Setup with creates the distribution package for windows
[Setup]
AppName=XPortScan
AppVerName=XPortScan 2
DefaultDirName={pf}\XPortScan
DefaultGroupName=XPortScan
UninstallDisplayIcon={app}\XPortScan.exe

[Files]
Source: "XPortScan.exe"; DestDir: "{app}"
Source: "portlist.txt"; DestDir: "{app}"
Source: "xportscan.exe.Manifest"; DestDir: "{app}";
Source: "helpfiles\*"; DestDir: "{app}\helpfiles";
[Icons]
Name: "{commonprograms}\XPortScan"; Filename: "{app}\XPortScan.exe"
Name: "{userdesktop}\XPortScan"; Filename: "{app}\XPortScan.exe"

[Run]
Filename: "{app}\xportscan.exe"; Description: "Launch XPortScan"; Flags: postinstall nowait
