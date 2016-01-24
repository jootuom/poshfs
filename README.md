# Filesystem module

Filesystem ACL module for PowerShell.

Please note that the Win32 260 character `MAX_PATH` [restriction](https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247\(v=vs.85\).aspx) applies.

Get-Help is included for every cmdlet.

## Add-FSPermissions
Add filesystem permissions to a user/group

## Remove-FSPermissions
Remove filesystem permissions from a user/group

## Get-FSPermissions
Get filesystem permissions

Example:
    
    
    Path: C:\Temp
    
    
    Identity                       Rights                         AccessType Inherited
    --------                       ------                         ---------- ---------
    AD\bob                         Modify, Synchronize            Allow      False
    NT AUTHORITY\SYSTEM            FullControl                    Allow      True
    BUILTIN\Administrators         FullControl                    Allow      True
    BUILTIN\Users                  ReadAndExecute, Synchronize    Allow      True
    BUILTIN\Users                  AppendData                     Allow      True
    BUILTIN\Users                  CreateFiles                    Allow      True
    CREATOR OWNER                  268435456                      Allow      True
    

## Set-FSPermissions
Set filesystem permissions (disable/enable inheritance)

## Compare-FSChildPermissions

Compare filesystem permissions between a directory and its children

Run this cmdlet on a directory to see how the permissions on its children differ.
You can see what ACL's have been added or removed to/from the children.
