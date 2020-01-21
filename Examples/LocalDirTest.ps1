Configuration LocalDirTest {
    Import-DscResource -Name DirectoryAccessControl
    Node 'localhost' 
    {
        DirectoryAccessControl 'TestDir'
        {
            Directory = 'C:\testdir'
            AccessControlInformation = @(
                DirectoryAccessControlInfo {
                    Principal = "BUILTIN\Administrators"
                    FileSystemRights = "FullControl"
                }
                DirectoryAccessControlInfo {
                    Principal = "NT AUTHORITY\SYSTEM"
                    FileSystemRights = "FullControl"
                }
                DirectoryAccessControlInfo {
                    Principal = "BUILTIN\Users"
                    FileSystemRights = "ReadAndExecute"
                }
            )
        }
    }
}
& LocalDirTests