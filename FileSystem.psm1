if (!(Get-FormatData "FSPerm*")) {
	# Prettier custom display for Get-FSPermissions
	Update-FormatData -Append (Join-Path $PSScriptRoot getfsperm.format.ps1xml)
	# Prettier custom display for Compare-FSPermissions
	Update-FormatData -Append (Join-Path $PSScriptRoot fspermcomp.format.ps1xml)
}

function Add-FSPermissions {
	<#
	.SYNOPSIS
	Adds filesystem permissions to specified object
	.DESCRIPTION
	This cmdlet adds filesystem permissions to the object
	that is specified.
	.EXAMPLE
	Set-FSPermissions "C:\Users" -Add "AD\Administrator" -AccessRight "ReadAndExecute"
	Allow AD\Administrator ReadAndExecute access to this object.
	.EXAMPLE
	Set-FSPermissions "C:\Users" -Add "AD\Administrator"
	Allow AD\Administrator Modify access to this object (default).
	.PARAMETER Object
	The object that will be modified.
	i.e. A directory or a file.
	.PARAMETER Identity
	Identity to add.
	.PARAMETER AccessRight
	The kind of access to grant.
	
	"Modify" by default.
	
	Most common options:
	--------------------
	"FullControl"
	"Modify"
	"ReadAndExecute"
	.PARAMETER InheritanceType
	The type of inheritance to add.
	
	"ContainerInherit, ObjectInherit" by default.
	
	NOTE: Don't change this if you don't know what you're doing!
	.PARAMETER AccessType
	The wanted access type: "Allow" or "Deny".
	
	"Allow" by default.
	#>
	[CmdletBinding(
		SupportsShouldProcess=$true,
		ConfirmImpact="Medium"
	)]
	Param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
		[Alias("FullName")]
		$Object,
		
		[Parameter(Position=1,Mandatory=$true)]
		[string] $Identity,
		
		[Parameter()]
		[string] $AccessRight = "Modify",
		
		[Parameter()]
		[string] $InheritanceType = "ContainerInherit, ObjectInherit",
		
		[Parameter()]
		[string] $AccessType = "Allow"
	)
	
	begin {
		
	}
	process {
		$path = (Resolve-Path $Object) -replace ".*\\\\", "\\"

		$acl = Get-Acl $path
		
		# Identity, Permission, Inheritance, Propagation, Type (Allow/Deny).
		$perm = New-Object System.Security.AccessControl.FileSystemAccessRule `
			-ArgumentList @(
				$Identity,
				$AccessRight,
				$InheritanceType,
				"None",
				$AccessType
			)
		
		$acl.SetAccessRule($perm)
		
		if ($pscmdlet.ShouldProcess($obj)) {
			Set-Acl -Path $path -AclObject $acl
		}
	}
	end {
		
	}
}

function Remove-FSPermissions {
	<#
	.SYNOPSIS
	Removes filesystem permissions from specified object
	.DESCRIPTION
	This cmdlet removes filesystem permissions from the object
	that is specified.
	Set-FSPermissions "C:\Users" -Remove "AD\Administrator"
	Remove AD\Administrator's access to this object.
	.PARAMETER Object
	The object that will be modified.
	i.e. A directory or a file.
	.PARAMETER Identity
	Identity to remove.
	#>
	[CmdletBinding(
		SupportsShouldProcess=$true,
		ConfirmImpact="Medium"
	)]
	Param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
		[Alias("FullName")]
		$Object,
		
		[Parameter(Position=1,Mandatory=$true)]
		[string] $Identity
	)
	
	begin {
		
	}
	process {
		$path = (Resolve-Path $Object) -replace ".*\\\\", "\\"
		
		$acl = Get-Acl $path
		
		$acl.Access |
			? { $_.IdentityReference -eq $Identity } |
			% { [void] $acl.RemoveAccessRule($_) }
		
		if ($pscmdlet.ShouldProcess($obj)) {
			Set-Acl -Path $path -AclObject $acl
		}
	}
	end {
		
	}
}

function Get-FSPermissions {
	<#
	.SYNOPSIS
	Lists filesystem permissions for specified object
	.DESCRIPTION
	Lists filesystem permissions for specified object.
	.EXAMPLE
	Get-FSPermissions C:\Users
	Lists permissions for the C:\Users directory.
	#>
	[CmdletBinding(
		
	)]
	Param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
		[Alias("FullName")]
		$Object
	)
	
	begin {
		
	}
	process {
		$path = (Resolve-Path $Object) -replace ".*\\\\", "\\"

		$acl = (Get-Acl $path).Access
		
		$acl | foreach {		
			$result = New-Object "PSObject" -Property @{
				Path = $path;
			
				Identity = $_.IdentityReference;
				Permissions = $_.FileSystemRights;
				PermType = $_.AccessControlType;
				Inherited = $_.IsInherited;
			}

			$result.PSTypeNames.Insert(0, "FSPermissionData")
				
			$result
		}
	}
	end {
		
	}
}

function Set-FSPermissions {
	<#
	.SYNOPSIS
	Sets filesystem permissions for specified object.
	.DESCRIPTION
	This cmdlet sets the filesystem permissions for the object
	that is specified: permission inheritance can be enabled or disabled.
	.EXAMPLE
	Set-FSPermissions "C:\Users" -DisableInheritance
	Stop inheriting permissions from the object's parent.
	.EXAMPLE
	Set-FSPermissions "C:\Users" -EnableInheritance
	Start inheriting permissions from the object's parent.
	.PARAMETER Object
	The object that will be modified.
	i.e. A directory or a file.
	.PARAMETER EnableInherit
	Enables permission inheritance for this object.
	.PARAMETER DisableInherit
	Disables permission inheritance for this object.
	#>
	[CmdletBinding(
		DefaultParameterSetName="DisableInherit",
		SupportsShouldProcess=$true,
		ConfirmImpact="Medium"
	)]
	Param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
		[Alias("FullName")]
		$Object,
		
		[Parameter(ParameterSetName="EnableInherit")]
		[switch] $EnableInherit,
		
		[Parameter(ParameterSetName="DisableInherit")]
		[switch] $DisableInherit
	)
	
	begin {
		
	}
	process {
		$path = (Resolve-Path $Object) -replace ".*\\\\", "\\"
		
		$acl = Get-Acl $path
	
		switch ($PSCmdlet.ParameterSetName) {
			"EnableInherit" {
				# Inherit yes/no, keep inherited perms yes/no.
				$acl.SetAccessRuleProtection($false, $false)
			}
			"DisableInherit" {
				$acl.SetAccessRuleProtection($true, $true)
			}
		}
		
		if ($pscmdlet.ShouldProcess($obj)) {
			Set-Acl -Path $path -AclObject $acl
		}
	}
	end {
		
	}
}

function Compare-FSChildPermissions {
	<#
	.SYNOPSIS
	Compare access permissions between child directories and 
	files and the given directory.
	.DESCRIPTION
	This cmdlet gets the permissions assigned for the given directory
	and then compares them to the permissions for the directory's
	children.
	.EXAMPLE
	Compare-FSChildPermissions "C:\Users" -Both
	Lists the permissions for every user's home directory,
	both added and removed ones.
	#>
	[CmdletBinding(
		
	)]
	Param(
		[Parameter(Position=0,Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
		[Alias("FullName")]
		$Object
	)
	
	begin {
		
	}
	process {
		$md = (Resolve-Path $Object) -replace ".*\\\\", "\\"
		
		$mdacl = @()
		
		# Collect list of main dir permissions by identity (name).
		(Get-Acl $md).Access | foreach {
			$mdacl += $_.IdentityReference
		}
		
		# Compare every child object.
		foreach ($chi in Get-ChildItem $md) {
			$chacl = @()
			
			# Collect list of child dir permissions by identity (name).
			(Get-Acl $chi.FullName).Access | foreach {
				$chacl += $_.IdentityReference
			}
			
			$diffadds = @()
			$diffrems = @()
			
			# Get added permission entries.
			$chacl | foreach {
				if ($mdacl -notcontains $_) {
					$diffadds += $_
				}
			}
	
			# Get removed permission entries.
			$mdacl | foreach {
				if ($chacl -notcontains $_) {
					$diffrems += $_
				}
			}
			
			$result = New-Object -Type "PSObject" -Property @{
				MainDirectory = $md;
				Name = $chi;
				Adds = $diffadds;
				Removes = $diffrems;
			}
			
			$result.PSTypeNames.Insert(0, "FSPermComparison")
			
			$result
		}
	}
	end {
		
	}
}
