[Setup]
AppId={{B7E5B2A4-3F1C-4D6E-9A2B-1C0D5E6F7A8B}
AppName=Enclave
AppVersion=1.7.1
AppPublisher=Tim
DefaultDirName={autopf}\Enclave
DefaultGroupName=Enclave
UninstallDisplayIcon={app}\Enclave.exe
OutputDir=Output
OutputBaseFilename=EnclaveSetup-1.7.1
SetupIconFile=src\EnclaveApp\AppIcon.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Files]
Source: "publish\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\Enclave"; Filename: "{app}\Enclave.exe"
Name: "{group}\Uninstall Enclave"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Enclave"; Filename: "{app}\Enclave.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Enclave.exe"; Description: "Launch Enclave"; Flags: nowait postinstall skipifsilent

[Registry]
Root: HKA; Subkey: "Software\Classes\.enclave\OpenWithProgids"; ValueType: string; ValueName: "Enclave.Archive"; ValueData: ""; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\Enclave.Archive"; ValueType: string; ValueName: ""; ValueData: "Enclave encrypted archive"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\Enclave.Archive\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\Enclave.exe,0"
Root: HKA; Subkey: "Software\Classes\Enclave.Archive\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\Enclave.exe"" ""%1"""
