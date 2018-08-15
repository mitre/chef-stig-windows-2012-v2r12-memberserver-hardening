#V-4443
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths" do
  values [{
    name: 'Machine',
    type: :multi_string,
    data: ['System\\CurrentControlSet\\Control\\ProductOptions']
  }]
  action :create
end

#V-3472
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\W32time\\Parameters" do
  values [{
    name: 'Type',
    type: :dword,
    data: 'NT5DS'
  }]
  action :create
  only_if {
    registry_key_exists?("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\W32time",
    :x86_64)
  }
end

#V-3339
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths" do
  values [{
    name: 'Machine',
    type: :multi_string,
    data: ["Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "System\\CurrentControlSet\\Control\\Print\\Printers", "System\\CurrentControlSet\\Services\\Eventlog", "Software\\Microsoft\\OLAP Server", "Software\\Microsoft\\Windows NT\\CurrentVersion\\Print", "System\\CurrentControlSet\\Control\\ContentIndex", "System\\CurrentControlSet\\Control\\Terminal Server", "System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig", "System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration", "Software\\Microsoft\\Windows NT\\CurrentVersion\\Perflib", "System\\CurrentControlSet\\Services\\SysmonLog"]
  }]
  action :create
end

#V-1075
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'ShutdownWithoutLogon',
    type: :dword,
    data: 0
  }]
  action :create
end



#V-1089
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'LegalNoticeText',
    type: :multi_string,
    data: ["You are accessing a U.S. Government (USG) Information System (IS) that is
  provided for USG-authorized use only.

  By using this IS (which includes any device attached to this IS), you consent
  to the following conditions:

  -The USG routinely intercepts and monitors communications on this IS for
  purposes including, but not limited to, penetration testing, COMSEC monitoring,
  network operations and defense, personnel misconduct (PM), law enforcement
  (LE), and counterintelligence (CI) investigations.

  -At any time, the USG may inspect and seize data stored on this IS.

  -Communications using, or data stored on, this IS are not private, are subject
  to routine monitoring, interception, and search, and may be disclosed or used
  for any USG-authorized purpose.

  -This IS includes security measures (e.g., authentication and access controls)
  to protect USG interests--not for your personal benefit or privacy.

  -Notwithstanding the above, using this IS does not constitute consent to PM, LE
  or CI investigative searching or monitoring of the content of privileged
  communications, or work product, related to personal representation or services
  by attorneys, psychotherapists, or clergy, and their assistants.  Such
  communications and work product are private and confidential.  See User
  Agreement for details."]
  }]
  action :create
end

#V-1090 -only if member of domain
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" do
  values [{
    name: 'CachedLogonsCount',
    type: :dword,
    data: 4
  }]
  action :create
end

#V-1093
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" do
  values [{
    name: 'RestrictAnonymous',
    type: :dword,
    data: 1
  }]
  action :create
end
 


#V-1136
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters" do
  values [{
    name: 'EnableForcedLogOff',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-1141
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" do
  values [{
    name: 'EnablePlainTextPassword',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-1145
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" do
  values [{
    name: 'AutoAdminLogon',
    type: :dword,
    data: 0
  }]
  action :create
end

registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" do
  values [{
    name: 'DefaultPassword',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-1151
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers" do
  values [{
    name: 'AddPrinterDrivers',
    type: :dword,
    data: 1
  }]
  action :create
end


#V-1153
registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa" do
  values [{
    name: 'LmCompatibilityLevel',
    type: :dword,
    data: 5
  }]
  action :create
end

#V-1154
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'DisableCAD',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-1157
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" do
  values [{
    name: 'scremoveoption',
    type: :dword,
    data: 2
  }]
  action :create
end

#V-1162
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" do
  values [{
    name: 'EnableSecuritySignature',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-1163
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" do
  values [{
    name: 'SealSecureChannel',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-1164
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" do
  values [{
    name: 'SignSecureChannel',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-1165
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" do
  values [{
    name: 'DisablePasswordChange',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-1166
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" do
  values [{
    name: 'EnableSecuritySignature',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-1168 - look into


#V-1171
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" do
  values [{
    name: 'AllocateDASD',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-1172
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" do
  values [{
    name: 'PasswordExpiryWarning',
    type: :dword,
    data: 14
  }]
  action :create
end

#V-1173
registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" do
  values [{
    name: 'ProtectionMode',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-1174
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" do
  values [{
    name: 'AutoDisconnect',
    type: :dword,
    data: 15
  }]
  action :create
end

#V-11806
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'DontDisplayLastUserName',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14225 - look into

#V-14228
registry_key "HKEY_LOCAL_MACHINE\\System\\Currentcontrolset\\Control\\Lsa" do
  values [{
    name: 'AuditBaseObjects',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-14229
registry_key "HKEY_LOCAL_MACHINE\\System\\Currentcontrolset\\Control\\Lsa" do
  values [{
    name: 'FullPrivilegeAuditing',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-14230
registry_key "HKEY_LOCAL_MACHINE\\System\\Currentcontrolset\\Control\\Lsa" do
  values [{
    name: 'scenoapplylegacyauditpolicy',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14232
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\IPSEC" do
  values [{
    name: 'NoDefaultExempt',
    type: :dword,
    data: 3
  }]
  action :create
end

#V-14234
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'FilterAdministratorToken',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14235
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'ConsentPromptBehaviorAdmin',
    type: :dword,
    data: 4
  }]
  action :create
end

#V-14236
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'ConsentPromptBehaviorUser',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-14237
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'EnableInstallerDetection',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14239
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'EnableSecureUIAPaths',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14240
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'EnableLUA',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14241
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'PromptOnSecureDesktop',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14242
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'EnableVirtualization',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14243
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI" do
  values [{
    name: 'EnumerateAdministrators',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-14247
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'DisablePasswordSaving',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14249
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'fDisableCdm',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14253
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc" do
  values [{
    name: 'RestrictRemoteClients',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14259
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers" do
  values [{
    name: 'DisableHTTPPrinting',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14260
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers" do
  values [{
    name: 'DisableWebPnPDownload',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14261
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DriverSearching" do
  values [{
    name: 'DontSearchWindowsUpdate',
    type: :dword,
    data: 1
  }]
  action :create
end


#V-14268
registry_key "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments" do
  values [{
    name: 'SaveZoneInformation',
    type: :dword,
    data: 2
  }]
  action :create
end

#V-14269
registry_key "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments" do
  values [{
    name: 'HideZoneInfoOnProperties',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-14270
registry_key "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments" do
  values [{
    name: 'ScanWithAntiVirus',
    type: :dword,
    data: 3
  }]
  action :create
end

#V-15666
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Peernet" do
  values [{
    name: 'Disabled',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-15667
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections" do
  values [{
    name: 'NC_AllowNetBridge_NLA',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-15672
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\EventViewer" do
  values [{
    name: 'MicrosoftEventVwrDisableLinks',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-15674
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" do
  values [{
    name: 'NoInternetOpenWith',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-15680 
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'LogonType',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-15682
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds" do
  values [{
    name: 'DisableEnclosureDownload',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

#V-15683
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" do
  values [{
    name: 'PreXPSP2ShellProtocolBehavior',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-15684
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer" do
  values [{
    name: 'SafeForScripting',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-15685
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer" do
  values [{
    name: 'EnableUserControl',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-15686
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer" do
  values [{
    name: 'DisableLUAPatching',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-15687
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WindowsMediaPlayer" do
  values [{
    name: 'GroupPrivacyAcceptance',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-15696
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD" do
  values [{
    name: 'AllowLLTDIOOnDomain',
    type: :dword,
    data: 0
  }]
  action :create
end

registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD" do
  values [{
    name: 'AllowLLTDIOOnPublicNet',
    type: :dword,
    data: 0
  }]
  action :create
end

registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD" do
  values [{
    name: 'EnableLLTDIO',
    type: :dword,
    data: 0
  }]
  action :create
end

registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD" do
  values [{
    name: 'ProhibitLLTDIOOnPrivateNet',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-15697
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD" do
  values [{
    name: 'AllowRspndrOnDomain',
    type: :dword,
    data: 0
  }]
  action :create
end


registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD" do
  values [{
    name: 'AllowRspndrOnPublicNet',
    type: :dword,
    data: 0
  }]
  action :create
end

registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD" do
  values [{
    name: 'EnableRspndr',
    type: :dword,
    data: 0
  }]
  action :create
end

registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LLTD" do
  values [{
    name: 'ProhibitRspndrOnPrivateNet',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-15698
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars" do
  values [{
    name: 'DisableInBand802DOT11Registrar',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars" do
  values [{
    name: 'DisableFlashConfigRegistrar',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars" do
  values [{
    name: 'DisableUPnPRegistrar',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars" do
  values [{
    name: 'DisableWPDRegistrar',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\Registrars" do
  values [{
    name: 'EnableRegistrars',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end


#V-15699
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WCN\\UI" do
  values [{
    name: 'DisableWcnUi',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

#V-15700
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings" do
  values [{
    name: 'AllowRemoteRPC',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

#V-15701
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings" do
  values [{
    name: 'DisableSystemRestore',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

#V-15702
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings" do
  values [{
    name: 'DisableSendGenericDriverNotFoundToWER',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

#V-15703
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DriverSearching" do
  values [{
    name: 'DontPromptForWindowsUpdate',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-15704
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\HandwritingErrorReports" do
  values [{
    name: 'PreventHandwritingErrorReports',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-15705
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" do
  values [{
    name: 'DCSettingIndex',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

#V-15706
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" do
  values [{
    name: 'ACSettingIndex',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

#V-15707
registry_key "HKEY_LOCAL_MACHINE\\Software\\policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'LoggingEnabled',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-15713
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows Defender\\SpyNet" do
  values [{
    name: 'SpyNetReporting',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end


#V-15718
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer" do
  values [{
    name: 'NoHeapTerminationOnCorruption',
    type: :dword,
    data: 0
  }]
  action :create
end


#V-15722
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\WMDRM" do
  values [{
    name: 'DisableOnline',
    type: :dword,
    data: 1
  }]
  action :create
end


#V-15727
registry_key "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" do
  values [{
    name: 'NoInPlaceSharing',
    type: :dword,
    data: 1
  }]
  action :create
end



#V-15991 
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'EnableUIADesktopToggle',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-15997
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'fDisableCcm',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-15998
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'fDisableLPT',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-15999
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'fDisablePNPRedir',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-16000
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'fEnableSmartCard',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-16008
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'ValidateAdminCodeSignatures',
    type: :dword,
    data: 0
  }]
  action :create
end


#V-16020
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\SQMClient\\Windows" do
  values [{
    name: 'CEIPEnable',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

#V-16021
registry_key "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0" do
  values [{
    name: 'NoImplicitFeedback',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

#V-16048
registry_key "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0" do
  values [{
    name: 'NoExplicitFeedback',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end


#V-21950
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters" do
  values [{
    name: 'SMBServerNameHardeningLevel',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-21951
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" do
  values [{
    name: 'UseMachineId',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-21952
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0" do
  values [{
    name: 'allownullsessionfallback',
    type: :dword,
    data: 0
  }]
  action :create
end


#V-21953
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u" do
  values [{
    name: 'AllowOnlineID',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-21954
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters" do
  values [{
    name: 'SupportedEncryptionTypes',
    type: :dword,
    data: 2_147_483_644
  }]
  recursive true
  action :create
end

#V-21955
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters" do
  values [{
    name: 'DisableIPSourceRouting',
    type: :dword,
    data: 2
  }]
  action :create
end

#V-21956
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip6\\Parameters" do
  values [{
    name: 'TcpMaxDataRetransmissions',
    type: :dword,
    data: 3
  }]
  action :create
end

#V-21960
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Network Connections" do
  values [{
    name: 'NC_StdDomainUserSetLocation',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-21961
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition" do
  values [{
    name: 'Force_Tunneling',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

#V-21963
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Printers" do
  values [{
    name: 'DoNotInstallCompatibleDriverFromWindowsUpdate',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-21964
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Device Metadata" do
  values [{
    name: 'PreventDeviceMetadataFromNetwork',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-21965
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DriverSearching" do
  values [{
    name: 'SearchOrderConfig',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-21967
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy" do
  values [{
    name: 'DisableQueryRemoteServer',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

#V-21969
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\ScriptedDiagnosticsProvider\\Policy" do
  values [{
    name: 'EnableQueryRemoteServer',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-21970
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" do
  values [{
    name: 'ScenarioExecutionEnabled',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

#V-21971
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\AppCompat" do
  values [{
    name: 'DisableInventory',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-21973
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer" do
  values [{
    name: 'NoAutoplayfornonVolume',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-21980
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Explorer" do
  values [{
    name: 'NoDataExecutionPrevention',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-22692
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" do
  values [{
    name: 'NoAutorun',
    type: :dword,
    data: 1
  }]
  action :create
end

#2374
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" do
  values [{
    name: 'NoDriveTypeAutoRun',
    type: :dword,
    data: 255
  }]
  action :create
end

#V-26283
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" do
  values [{
    name: 'RestrictAnonymousSAM',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-26359
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'LegalNoticeCaption',
    type: :multi_string,
    data: ['DoD Notice and Consent Banner, US Department of Defense Warning
  Statement, or a site-defined equivalent.']
  }]
  action :create
end

#V-26575
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition" do
  values [{
    name: '6to4_State',
    type: :dword,
    data: 'Disabled'
  }]
  action :create
end


#V-26576
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\IPHTTPS\\IPHTTPSInterface" do
  values [{
    name: 'IPHTTPS_ClientState',
    type: :dword,
    data: 3
  }]
  recursive true
  action :create
end

#V-26577
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition" do
  values [{
    name: 'ISATAP_State',
    type: :dword,
    data: 'Disabled'
  }]
  action :create
end

#V-26578
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition" do
  values [{
    name: 'Teredo_State',
    type: :dword,
    data: 'Disabled'
  }]
  action :create
end

#V-26579
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application" do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 32768
  }]
  recursive true
  action :create
end

#V-26580
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security" do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 196608
  }]
  recursive true
  action :create
end

#V-26581
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Setup" do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 32768
  }]
  recursive true
  action :create
end

#V-26582
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System" do
  values [{
    name: 'MaxSize',
    type: :dword,
    data: 32768
  }]
  recursive true
  action :create
end


#V-28504
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DeviceInstall\\Settings" do
  values [{
    name: 'DisableSendRequestAdditionalSoftwareToWER',
    type: :dword,
    data: 1
  }]
  action :create
end


#V-3338
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters" do
  values [{
    name: 'NullSessionPipes',
    type: :multi_string,
    data: ['']
  }]
  action :create
end

#V-3340
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters" do
  values [{
    name: 'NullSessionShares',
    type: :multi_string,
    data: ['']
  }]
  action :create
end

#V-3343
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'fAllowToGetHelp',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-3344
registry_key "HKEY_LOCAL_MACHINE\\System\\Currentcontrolset\\Control\\Lsa" do
  values [{
    name: 'Limitblankpassworduse',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3373
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" do
  values [{
    name: 'MaximumPasswordAge',
    type: :dword,
    data: 30
  }]
  action :create
end

#V-3374
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" do
  values [{
    name: 'RequireStrongKey',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3376
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" do
  values [{
    name: 'DisableDomainCreds',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3377
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" do
  values [{
    name: 'EveryoneIncludesAnonymous',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-3378
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" do
  values [{
    name: 'ForceGuest',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-3379
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" do
  values [{
    name: 'NoLMHash',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3382
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0" do
  values [{
    name: 'NTLMMinClientSec',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3383
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\FIPSAlgorithmPolicy" do
  values [{
    name: 'Enabled',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3385
registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel" do
  values [{
    name: 'ObCaseInsensitive',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3449
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'fSingleSessionPerUser',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3453
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'fPromptForPassword',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3454
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'MinEncryptionLevel',
    type: :dword,
    data: 3
  }]
  action :create
end

#V-3455
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'PerSessionTempDir',
    type: :dword,
    data: 1
  }]
  action :create
end


#V-3456
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'DeleteTempDirsOnExit',
    type: :dword,
    data: 1
  }]
  action :create
end


#V-3469
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\system" do
  values [{
    name: 'DisableBkGndGroupPolicy',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-3470
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'fAllowUnsolicited',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-3479
registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" do
  values [{
    name: 'SafeDllSearchMode',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3480
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsMediaPlayer" do
  values [{
    name: 'DisableAutoUpdate',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3481
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsMediaPlayer" do
  values [{
    name: 'PreventCodecDownload',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-34974
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Installer" do
  values [{
    name: 'AlwaysInstallElevated',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-36439
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'LocalAccountTokenFilterPolicy',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-36656
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Control
  Panel\\Desktop" do
  values [{
    name: 'ScreenSaveActive',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

#V-36656
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Control
  Panel\\Desktop" do
  values [{
    name: 'ScreenSaverIsSecure',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-3666
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0" do
  values [{
    name: 'NTLMMinServerSec',
    type: :dword,
    data: 537395200
  }]
  action :create
end

#V-36673
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" do
  values [{
    name: 'EnableIPAutoConfigurationLimits',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-36677
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Servicing" do
  values [{
    name: 'UseWindowsUpdate',
    type: :dword,
    data: 2
  }]
  action :create
end

#V-36677
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Servicing" do
  values [{
    name: 'UseWindowsUpdate',
    type: :dword,
    data: 2
  }]
  action :create
end

#V-36678
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\DriverSearching" do
  values [{
    name: 'DriverServerSelection',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-36679
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Policies\\EarlyLaunch" do
  values [{
    name: 'DriverLoadPolicy',
    type: :dword,
    data: 1
  }]
  action :create
end


#V-36680
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer" do
  values [{
    name: 'NoUseStoreOpenWith',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-36681
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Control Panel\\International" do
  values [{
    name: 'BlockUserInputMethodsForSignIn',
    type: :dword,
    data: 1
  }]
  recursive true
  action :create
end

#V-36684
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System" do
  values [{
    name: 'EnumerateLocalUsers',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-36687
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System" do
  values [{
    name: 'DisableLockScreenAppNotifications',
    type: :dword,
    data: 1
  }]
  action :create
end


#V-36696
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\AppCompat" do
  values [{
    name: 'DisablePcaUI',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-36697
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Appx" do
  values [{
    name: 'AllowAllTrustedApps',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-36698
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Biometrics" do
  values [{
    name: 'Enabled',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-36700
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\CredUI" do
  values [{
    name: 'DisablePasswordReveal',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-36707
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\System" do
  values [{
    name: 'EnableSmartScreen',
    type: :dword,
    data: 2
  }]
  action :create
end

#V-36708
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\LocationAndSensors" do
  values [{
    name: 'DisableLocation',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-36709
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Internet Explorer\\Feeds" do
  values [{
    name: 'AllowBasicAuthInClear',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

#V-36710

  registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore" do
  values [{
    name: 'AutoDownload',
    type: :dword,
    data: 2
  }]
  action :create
  end



  registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore\\WindowsUpdate" do
  values [{
    name: 'AutoDownload',
    type: :dword,
    data: 2
  }]
  action :create
  end


#V-36711
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsStore" do
  values [{
    name: 'RemoveWindowsStore',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-36712
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client" do
  values [{
    name: 'AllowBasic',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

#V-36713
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client" do
  values [{
    name: 'AllowUnencryptedTraffic',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-36714
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client" do
  values [{
    name: 'AllowDigest',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-36718
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service" do
  values [{
    name: 'AllowBasic',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-36719
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service" do
  values [{
    name: 'AllowUnencryptedTraffic',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-36720
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service" do
  values [{
    name: 'DisableRunAs',
    type: :dword,
    data: 1
  }]
  action :create
end


#V-36773
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'InactivityTimeoutSecs',
    type: :dword,
    data: 900
  }]
  action :create
end

#V-36776
registry_key "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" do
  values [{
    name: 'NoCloudApplicationNotification',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-36777
registry_key "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\PushNotifications" do
  values [{
    name: 'NoToastApplicationNotificationOnLockScreen',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-40204
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'RedirectOnlyDefaultClientPrinter',
    type: :dword,
    data: 1
  }]
  action :create
end


#V-4108
registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security" do
  values [{
    name: 'WarningLevel',
    type: :dword,
    data: 90
  }]
  action :create
end

#V-4110
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" do
  values [{
    name: 'DisableIPSourceRouting',
    type: :dword,
    data: 2
  }]
  action :create
end

#V-4111
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" do
  values [{
    name: 'EnableICMPRedirect',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-4112
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" do
  values [{
    name: 'PerformRouterDiscovery',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-4113
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" do
  values [{
    name: 'KeepAliveTime',
    type: :dword,
    data: 300000
  }]
  action :create
end

#V-4116
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netbt\\Parameters" do
  values [{
    name: 'NoNameReleaseOnDemand',
    type: :dword,
    data: 1
  }]
  action :create
end


#V-43238 
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization" do
  values [{
    name: 'NoLockScreenSlideshow',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-43239
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit" do
  values [{
    name: 'ProcessCreationIncludeCmdLine_Enabled',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-43240

  registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" do
  values [{
    name: 'DontDisplayNetworkSelectionUI',
    type: :dword,
    data: 1
  }]
  action :create
  end


#V-43241

  registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'MSAOptional',
    type: :dword,
    data: 1
  }]
  action :create
  end


#V-43245

  registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" do
  values [{
    name: 'DisableAutomaticRestartSignOn',
    type: :dword,
    data: 1
  }]
  action :create
  end


#V-4438
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters" do
  values [{
    name: 'TcpMaxDataRetransmissions',
    type: :dword,
    data: 3
  }]
  action :create
end

#V-4442
registry_key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" do
  values [{
    name: 'ScreenSaverGracePeriod',
    type: :dword,
    data: 5
  }]
  action :create
end

#V-4445
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services" do
  values [{
    name: 'fEncryptRPCTraffic',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-4448
registry_key "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" do
  values [{
    name: 'NoGPOListChanges',
    type: :dword,
    data: 0
  }]
  recursive true
  action :create
end

#V-57639
registry_key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Cryptography" do
  values [{
    name: 'ForceKeyProtection',
    type: :dword,
    data: 2
  }]
  action :create
end

#V-6831
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" do
  values [{
    name: 'RequireSignOrSeal',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-6832
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" do
  values [{
    name: 'RequireSecuritySignature',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-6833
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" do
  values [{
    name: 'RequireSecuritySignature',
    type: :dword,
    data: 1
  }]
  action :create
end

#V-6834
registry_key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters" do
  values [{
    name: 'restrictnullsessaccess',
    type: :dword,
    data: 1
  }]
  action :create
end

 #V-72753
registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest" do
  values [{
    name: 'UseLogonCredential',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-73519
registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" do
  values [{
    name: 'SMB1',
    type: :dword,
    data: 0
  }]
  action :create
end

#V-73523
registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\mrxsmb10" do
  values [{
    name: 'Start',
    type: :dword,
    data: 4
  }]
  action :create
end

registry_key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation" do
  values [{
    name: 'DependOnService',
    type: :dword,
    data: 'Bowser
  MRxSmb20
  NSI'
  }]
  action :create
end
