#V-36722#V-36723, V-36724
powershell_script 'V-36722, 36723, 36724' do
 
  code <<-EOH
  $systemroot = $Env:SYSTEMROOT
  $FolderPath = "$systemroot\\SYSTEM32\\WINEVT\\LOGS"
 
  $ACL = (Get-Item $FolderPath).GetAccessControl('Access')

  $NonCompliantRules = $ACL.Access | Where-Object {
  $_.IdentityReference -notlike "*Administrators*" -and $_.IdentityReference -notlike "*Eventlog*"
  }

  #For every Principal found that's not supposed to be there, remove the ACE
  If([string]::IsNullOrEmpty($NonCompliantRules)){}

  Else{
    ForEach($NonCompliantRule in $NonCompliantRules){

  $ACl.RemoveAccessRule($NonCompliantRule) | out-null
  }}

  $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
  $acl.SetAccessRule($AccessRule)


  $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Authenticated Users","Read, Synchronize","Allow")
  $acl.SetAccessRule($AccessRule)

  $acl | Set-Acl -Path "$systemroot\\SYSTEM32\\WINEVT\\LOGS"

  EOH
end


#V-40177 
powershell_script 'V-40177 - part 1' do
  code <<-EOH

  $acl = Get-Acl "C:\\Program Files"

  $NonCompliantRules = $ACL.Access | Where-Object {
  $_.IdentityReference -notlike "*Administrators*" -and $_.IdentityReference -notlike "*Creator Owner*" -and $_.IdentityReference -notlike "*SYSTEM*" -and $_.IdentityReference -notlike "*Users*" -and $_.IdentityReference -notlike "*TrustedInstaller*" -and $_.IdentityReference -notlike "*APPLICATION PACKAGE AUTHORITY*"
  }

  #For every Principal found that's not supposed to be there, remove the ACE
  If([string]::IsNullOrEmpty($NonCompliantRules)){}

  Else{
    ForEach($NonCompliantRule in $NonCompliantRules){

  $ACl.RemoveAccessRule($NonCompliantRule) | out-null
  }}

  $acl = Get-Acl "C:\\Program Files (x86)"

  $NonCompliantRules = $ACL.Access | Where-Object {
  $_.IdentityReference -notlike "*Administrators*" -and $_.IdentityReference -notlike "*Creator Owner*" -and $_.IdentityReference -notlike "*SYSTEM*" -and $_.IdentityReference -notlike "*Users*" -and $_.IdentityReference -notlike "*TrustedInstaller*" -and $_.IdentityReference -notlike "*APPLICATION PACKAGE AUTHORITY*"
  }

  #For every Principal found that's not supposed to be there, remove the ACE
  If([string]::IsNullOrEmpty($NonCompliantRules)){}

  Else{
    ForEach($NonCompliantRule in $NonCompliantRules){

  $ACl.RemoveAccessRule($NonCompliantRule) | out-null
  }}

  EOH
end

#V-40178
powershell_script 'V-40178' do
  code <<-EOH

  $FolderPath = "C:\\"
 
  $ACL = (Get-Item $FolderPath).GetAccessControl('Access')
   $acl.SetAccessRuleProtection($true,$false)

  $NonCompliantRules = $ACL.Access | Where-Object {
  $_.IdentityReference -notlike "*Administrators*"
  }

  #For every Principal found that's not supposed to be there, remove the ACE
  If([string]::IsNullOrEmpty($NonCompliantRules)){}

  Else{
    ForEach($NonCompliantRule in $NonCompliantRules){

  $ACl.RemoveAccessRule($NonCompliantRule) | out-null
  }}

  $AccessRule = New-Object  system.security.accesscontrol.FileSystemAccessRule("CREATOR OWNER","FullControl","ContainerInherit, ObjectInherit","InheritOnly","Allow")
  $acl.SetAccessRule($AccessRule)

  $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
  $acl.SetAccessRule($AccessRule)

  $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","AppendData","Allow")
  $acl.AddAccessRule($AccessRule)


  $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","CreateFiles","Allow")
  $acl.AddAccessRule($AccessRule)

  $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users","ReadAndExecute","Allow")
  $acl.AddAccessRule($AccessRule)

   $acl | Set-Acl -Path "C:\\"

  EOH
end

#V-40179
powershell_script 'V-4019' do
  code <<-EOH

  $FolderPath = "C:\\Windows"
 
  $ACL = (Get-Item $FolderPath).GetAccessControl('Access')
   $acl.SetAccessRuleProtection($true,$false)

    $NonCompliantRules = $ACL.Access | Where-Object {
  $_.IdentityReference -notlike "*Administrators*" -and $_.IdentityReference -notlike "*Creator Owner*" -and $_.IdentityReference -notlike "*SYSTEM*" -and $_.IdentityReference -notlike "*Users*" -and $_.IdentityReference -notlike "*TrustedInstaller*" -and $_.IdentityReference -notlike "*APPLICATION PACKAGE AUTHORITY*"
  }

  #For every Principal found that's not supposed to be there, remove the ACE
  If([string]::IsNullOrEmpty($NonCompliantRules)){}

  Else{
    ForEach($NonCompliantRule in $NonCompliantRules){

  $ACl.RemoveAccessRule($NonCompliantRule) | out-null
  }}

  EOH
end

#V-57721
powershell_script 'V-57721' do
  code <<-EOH

  $systemroot = $Env:SYSTEMROOT
  $FolderPath = "$systemroot\\SYSTEM32\\Eventvwr.exe"

 
  $ACL = (Get-Item $FolderPath).GetAccessControl('Access')
   $acl.SetAccessRuleProtection($true,$false)

    $NonCompliantRules = $ACL.Access | Where-Object {
  $_.IdentityReference -notlike "*Administrators*" -and $_.IdentityReference -notlike "*Creator Owner*" -and $_.IdentityReference -notlike "*SYSTEM*" -and $_.IdentityReference -notlike "*Users*" -and $_.IdentityReference -notlike "*TrustedInstaller*" -and $_.IdentityReference -notlike "*APPLICATION PACKAGE AUTHORITY*"
  }

  #For every Principal found that's not supposed to be there, remove the ACE
  If([string]::IsNullOrEmpty($NonCompliantRules)){}

  Else{
    ForEach($NonCompliantRule in $NonCompliantRules){

  $ACl.RemoveAccessRule($NonCompliantRule) | out-null
  }}

  EOH
end

#V-32282- part1
powershell_script 'V-32282- part1' do
  code <<-EOH

  $acl = Get-Acl "HKLM:\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components"

  $acl.SetAccessRuleProtection($true,$false)

  $usersid = New-Object System.Security.Principal.Ntaccount ("ALL APPLICATION PACKAGES")

  $acl.PurgeAccessRules($usersid)
  
  $NonCompliantRules = $ACL.Access | Where-Object {
  $_.IdentityReference -notlike "*Administrators*"
  }

  #For every Principal found that's not supposed to be there, remove the ACE
  If([string]::IsNullOrEmpty($NonCompliantRules)){}

  Else{
    ForEach($NonCompliantRule in $NonCompliantRules){

  $ACl.RemoveAccessRule($NonCompliantRule) | out-null
  }}
  $AccessRule = New-Object  system.security.accesscontrol.registryaccessrule("CREATOR OWNER","FullControl","ContainerInherit, ObjectInherit","InheritOnly","Allow")
  $acl.SetAccessRule($AccessRule)

  $AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule("Users","ReadKey","Allow")
  $acl.SetAccessRule($AccessRule)

  $AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule("Administrators","FullControl","Allow")
  $acl.SetAccessRule($AccessRule)

  $AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule("SYSTEM","FullControl","Allow")
  $acl.SetAccessRule($AccessRule)


  $AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule("ALL APPLICATION PACKAGES","ReadKey","Allow")
  $acl.SetAccessRule($AccessRule)

  $acl | Set-Acl -Path "HKLM:\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components"
  EOH
end

#V-26070
powershell_script 'V-26070' do
  code <<-EOH

  $acl = Get-Acl "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

  $usersid = New-Object System.Security.Principal.Ntaccount ("ALL APPLICATION PACKAGES")

  $acl.PurgeAccessRules($usersid)
  
  $NonCompliantRules = $ACL.Access | Where-Object {
  $_.IdentityReference -notlike "*Administrators*" -and $_.IdentityReference -notlike "*TrustedInstaller*"
  }

  #For every Principal found that's not supposed to be there, remove the ACE
  If([string]::IsNullOrEmpty($NonCompliantRules)){}

  Else{
    ForEach($NonCompliantRule in $NonCompliantRules){

  $ACl.RemoveAccessRule($NonCompliantRule) | out-null
  }}
 

  $AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule("Users","ReadKey","Allow")
  $acl.SetAccessRule($AccessRule)

  $AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule("Administrators","FullControl","Allow")
  $acl.SetAccessRule($AccessRule)

  $AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule("SYSTEM","FullControl","Allow")
  $acl.SetAccessRule($AccessRule)


  $AccessRule = New-Object System.Security.AccessControl.RegistryAccessRule("ALL APPLICATION PACKAGES","ReadKey","Allow")
  $acl.SetAccessRule($AccessRule)

  $acl | Set-Acl -Path "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
  EOH
end


