enum Access
{
    Allow
    Deny
}

class DirectoryAccessControlInfo
{
    [DscProperty(Mandatory)]
    [string]$Principal
    [DscProperty(Mandatory)]
    [string]$FileSystemRights
    [DscProperty()]
    [Access]$AccessControlType = "Allow"


    [string] GetAccessRuletoString() {
        $Rule = $this.GetAccessRule()
        $string = "$($Rule.IdentityReference);$($Rule.AccessControlType);$($Rule.FileSystemRights)"
        Return $string
    }

    [System.Security.AccessControl.FileSystemAccessRule] GetAccessRule() {
        if($this.Principal -match "^\.\\"){
            $stringprincipal = $this.Principal -replace "^\.", $env:COMPUTERNAME
        }
        else{
            $stringprincipal = $this.Principal
        }
        $Rule = New-Object -ErrorAction Stop System.Security.AccessControl.FileSystemAccessRule($stringprincipal, $this.FileSystemRights, 'ObjectInherit, ContainerInherit', 'None', $this.AccessControlType)
        Return $Rule
    }
}

[DscResource()]
class DirectoryAccessControl {
    [DscProperty()]
    [bool]$AllowInheritance = $false

    [DscProperty(Key, Mandatory)]
    [string]$Directory

    [DscProperty(Mandatory)]
    [DirectoryAccessControlInfo[]]$AccessControlInformation


    [void] Set() {
        Write-Verbose "Setting ACL on $($this.Directory)"
        $Acl = New-Object System.Security.AccessControl.DirectorySecurity -ErrorAction Stop
        if($this.AllowInheritance){
            $Acl.SetAccessRuleProtection($false, $false)
        }
        else{
            $Acl.SetAccessRuleProtection($true, $true)
        }

        #Add Aces to list
        $this.AccessControlInformation | ForEach-Object {
            $rule = $_.GetAccessRule()
            Write-Verbose "...Adding $($rule.IdentityReference) with $($rule.AccessControlType), $($rule.FileSystemRights)"
            $Acl.AddAccessRule($rule)
        }
        #Set the ACL
        Set-Acl -Path $this.Directory -AclObject $Acl -ErrorAction Stop
    }

    [bool] Test() {
        $Result = $false
        if(!(Test-Path -PathType Container -Path $this.Directory)){
            $Result = $true
        }
        else{
            $DesiredRules = $this.AccessControlInformation | ForEach-Object {
                $_.GetAccessRuletoString()
            }
            $ActualRulesInfo = $this.GetDirectoryAclInfo()
            # If Inheritance isnt correct, this is not compliant
            If($ActualRulesInfo.Inheritance -ne $this.AllowInheritance){
                $Result = $false
            }
            else{
                $comparison = Compare-Object -ReferenceObject $DesiredRules -DifferenceObject $ActualRulesInfo.Rules
                if($null -eq $comparison){
                    $Result = $true
                }
            }
        }
        Return $Result
    }

    [DirectoryAccessControl] Get(){
        Return $this
    }

    [hashtable] GetDirectoryAclInfo(){
        $Acl = Get-Acl $this.Directory -ErrorAction Stop
        $RulesStrings = $acl.Access| Where-Object {$_.IsInherited -eq $false} | ForEach-Object {
            "$($_.IdentityReference);$($_.AccessControlType);$($_.FileSystemRights)"
        }
        $Result = @{
            Rules = $RulesStrings
            Inheritance = !($Acl.AreAccessRulesProtected)
        }
        Return $Result
    }
}