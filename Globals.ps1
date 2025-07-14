#--------------------------------------------
# Declare Global Variables and Functions here
#--------------------------------------------


#Sample function that provides the location of the script
function Get-ScriptDirectory
{
<#
	.SYNOPSIS
		Get-ScriptDirectory returns the proper location of the script.

	.OUTPUTS
		System.String
	
	.NOTES
		Returns the correct path within a packaged executable.
#>
	[OutputType([string])]
	param ()
	if ($null -ne $hostinvocation)
	{
		Split-Path $hostinvocation.MyCommand.path
	}
	else
	{
		Split-Path $script:MyInvocation.MyCommand.Path
	}
}

#Inventory users with unusual PrimaryGroup members - USERS
function Get-UnusualPrimaryGroupUsers
{
	param (
		[Parameter(Mandatory = $false)]
		[switch]$CountOnly,
		[Parameter(Mandatory = $false)]
		[int[]]$ExpectedPrimaryGroups = @(512, 513, 514, 515, 516, 517, 518, 519, 520, 521)
	)
	
	$users = Get-ADUser -Filter * -Properties PrimaryGroupID, samAccountName
	
	$unusualUsers = $users | Where-Object {
		$_.PrimaryGroupID -and ($ExpectedPrimaryGroups -notcontains $_.PrimaryGroupID)
	}
	
	if ($CountOnly)
	{
		return @($unusualUsers).Count
	}
	else
	{
		return $unusualUsers | Select-Object samAccountName, PrimaryGroupID
	}
}
#Inventory users with unusual PrimaryGroup members - Computers
function Get-UnusualPrimaryGroupComputers
{
	param (
		[Parameter(Mandatory = $false)]
		[switch]$CountOnly,
		[Parameter(Mandatory = $false)]
		[int[]]$ExpectedPrimaryGroups = @(512, 513, 514, 515, 516, 517, 518, 519, 520, 521) # 515 = Domain Computers
	)
	
	# Get all computers in the domain
	$computers = Get-ADComputer -Filter * -Properties PrimaryGroupID, Name
	
	# Find computers whose PrimaryGroupID is not in the expected list
	$unusualComputers = $computers | Where-Object {
		$_.PrimaryGroupID -and ($ExpectedPrimaryGroups -notcontains $_.PrimaryGroupID)
	}
	
	if ($CountOnly)
	{
		return @($unusualComputers).Count
	}
	else
	{
		return $unusualComputers | Select-Object Name, PrimaryGroupID
	}
}
#Checks if NTLMv1 and LM authentication protocols are banned on all Domain Controllers in the domain.
function Check-NTLMv1-LM-Banned-AllDCs
{
    <#
    .SYNOPSIS
        Checks if NTLMv1 and LM authentication protocols are banned on all Domain Controllers in the domain.

    .DESCRIPTION
        This function enumerates all domain controllers (DCs) and checks their registry settings
        to ensure NTLMv1 and LM protocols are disabled (LmCompatibilityLevel=5 and NoLMHash=1).

    .OUTPUTS
        Returns a summary object for each DC with DC name, compliant status, and details.

    .EXAMPLE
        Check-NTLMv1-LM-Banned-AllDCs
    #>
	# Requires ActiveDirectory module and suitable permissions!
	
	$dcs = Get-ADDomainController -Filter *
	$baseKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
	
	$scriptBlock = {
		param ($baseKey)
		$result = [PSCustomObject]@{
			DCName			     = $env:COMPUTERNAME
			LmCompatibilityLevel = $null
			NoLMHash			 = $null
			Compliant		     = $false
			Details			     = ""
		}
		$lmLevel = (Get-ItemProperty -Path $baseKey -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
		$noLMHash = (Get-ItemProperty -Path $baseKey -Name "NoLMHash" -ErrorAction SilentlyContinue).NoLMHash
		
		$result.LmCompatibilityLevel = $lmLevel
		$result.NoLMHash = $noLMHash
		
		if ($lmLevel -eq 5 -and $noLMHash -eq 1)
		{
			$result.Compliant = $true
			$result.Details = "NTLMv1 and LM banned."
		}
		else
		{
			$result.Compliant = $false
			$result.Details = "Non-compliant: LmCompatibilityLevel=$lmLevel, NoLMHash=$noLMHash"
		}
		return $result
	}
	
	$results = @()
	foreach ($dc in $dcs)
	{
		Write-Host "Checking $($dc.HostName)..."
		try
		{
			$output = Invoke-Command -ComputerName $dc.HostName -ScriptBlock $scriptBlock -ArgumentList $baseKey -ErrorAction Stop
			$results += $output
		}
		catch
		{
			$results += [PSCustomObject]@{
				DCName			     = $dc.HostName
				LmCompatibilityLevel = $null
				NoLMHash			 = $null
				Compliant		     = $false
				Details			     = "Error: $_"
			}
		}
	}
	return $results
}

#Check clusteraccount
function Test-ClusterPasswordChangeCompliance
{
	param (
		[Parameter(Mandatory = $false)]
		[int]$AccountAgeYears = 3,
		[Parameter(Mandatory = $false)]
		[int]$LoginWindowDays = 45,
		[Parameter(Mandatory = $false)]
		[switch]$CountOnly
	)
	
	$now = Get-Date
	$minAccountCreated = $now.AddYears(-$AccountAgeYears)
	$minLastLogon = $now.AddDays(-$LoginWindowDays)
	
	$clusters = Get-ADUser -Filter * -Properties UserAccountControl, whenCreated, lastlogontimestamp, PasswordLastSet, samAccountName
	
	$nonCompliant = @()
	
	foreach ($cluster in $clusters)
	{
		# Skip disabled accounts (flag 2 is ACCOUNTDISABLE)
		if (($cluster.UserAccountControl -band 2) -eq 2) { continue }
		
		# Make sure whenCreated and lastlogontimestamp exist
		if (-not $cluster.whenCreated -or -not $cluster.lastlogontimestamp) { continue }
		
		$whenCreated = [datetime]$cluster.whenCreated
		$lastLogon = [datetime]::FromFileTime($cluster.lastlogontimestamp)
		$pwdLastSet = if ($cluster.PasswordLastSet) { [datetime]$cluster.PasswordLastSet }
		else { $null }
		
		# Condition 1: Created ≥ 3 years ago
		if ($whenCreated -gt $minAccountCreated) { continue }
		
		# Condition 2: Used in last 45 days
		if ($lastLogon -lt $minLastLogon) { continue }
		
		# Condition 3: Password last set ≥ 3 years before last login
		if ($pwdLastSet -and ($pwdLastSet -le $lastLogon.AddYears(-$AccountAgeYears)))
		{
			$nonCompliant += [PSCustomObject]@{
				samAccountName  = $cluster.samAccountName
				whenCreated	    = $whenCreated
				lastLogon	    = $lastLogon
				PasswordLastSet = $pwdLastSet
			}
		}
	}
	
	if ($CountOnly)
	{
		return @($nonCompliant).Count
	}
	else
	{
		return $nonCompliant
	}
}

#computers with old password
function Get-ComputersWithIrregularPasswordChange
{
	param (
		[Parameter(Mandatory = $false)]
		[int]$MaxPasswordAgeDays = 30,
		[Parameter(Mandatory = $false)]
		[switch]$CountOnly
	)
	
	$threshold = (Get-Date).AddDays(-$MaxPasswordAgeDays)
	$computers = Get-ADComputer -Filter * -Properties PasswordLastSet, Name
	
	$irregular = $computers | Where-Object {
		$_.PasswordLastSet -lt $threshold
	}
	
	if ($CountOnly)
	{
		return @($irregular).Count
	}
	else
	{
		$irregular | Select-Object Name, PasswordLastSet
	}
}

#inactive adobjects
function Get-InactiveADObjects
{
	param (
		[Parameter(Mandatory = $true)]
		[ValidateSet("User", "Computer")]
		[string]$Type,
		[Parameter(Mandatory = $false)]
		[switch]$CountOnly,
		[Parameter(Mandatory = $false)]
		[string[]]$Exclude = @('krbtgt', 'guest')
	)
	
	if ($Type -eq "User")
	{
		$objects = Get-ADUser -Filter * -Properties UserAccountControl, Name
	}
	elseif ($Type -eq "Computer")
	{
		$objects = Get-ADComputer -Filter * -Properties UserAccountControl, Name
	}
	else
	{
		throw "Type must be 'User' or 'Computer'."
	}
	
	# UserAccountControl flag 2 means disabled
	$inactive = $objects | Where-Object {
		($_.UserAccountControl -band 2) -eq 2 -and
		($Exclude -notcontains $_.Name.ToLower())
	}
	
	if ($CountOnly)
	{
		return @($inactive).Count
	}
	else
	{
		$inactive | Select-Object Name, UserAccountControl
	}
}

#inactive DomainControllers
function Get-InactiveDomainControllers
{
	param (
		[Parameter(Mandatory = $false)]
		[switch]$CountOnly
	)
	
	$dcs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
	
	$inactiveDCs = @()
	
	foreach ($dcName in $dcs)
	{
		$dcAccount = Get-ADComputer -Identity $dcName -Properties UserAccountControl, Name
		if (($dcAccount.UserAccountControl -band 2) -eq 2)
		{
			$inactiveDCs += $dcAccount
		}
	}
	
	if ($CountOnly)
	{
		return @($inactiveDCs).Count
	}
	else
	{
		$inactiveDCs | Select-Object Name, UserAccountControl
	}
}

#DC missing Subnet
function Get-DCsWithMissingSubnet
{
	param (
		[Parameter(Mandatory = $false)]
		[switch]$CountOnly
	)
	
	$subnets = Get-ADReplicationSubnet -Filter * | Select-Object -ExpandProperty Name
	
	$subnetObjs = $subnets | ForEach-Object {
		if ($_ -match "^(.+)/(\d+)$")
		{
			$ip = $Matches[1]
			$prefix = [int]$Matches[2]
			[PSCustomObject]@{
				IPAddress    = $ip
				PrefixLength = $prefix
			}
		}
	}
	
	$DCs = Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, IPv6Address
	
	$missingSubnetDCs = @()
	
	foreach ($dc in $DCs)
	{
		$ipList = @()
		if ($dc.IPv4Address) { $ipList += $dc.IPv4Address }
		if ($dc.IPv6Address) { $ipList += $dc.IPv6Address }
		
		$found = $false
		foreach ($ip in $ipList)
		{
			foreach ($subnet in $subnetObjs)
			{
				try
				{
					$ipObj = [System.Net.IPAddress]::Parse($ip)
					$subnetObj = [System.Net.IPAddress]::Parse($subnet.IPAddress)
					$ipBytes = $ipObj.GetAddressBytes()
					$subnetBytes = $subnetObj.GetAddressBytes()
					$prefixLen = $subnet.PrefixLength
					
					$bitsToCheck = [math]::Floor($prefixLen / 8)
					$bitsLeft = $prefixLen % 8
					$match = $true
					for ($i = 0; $i -lt $bitsToCheck; $i++)
					{
						if ($ipBytes[$i] -ne $subnetBytes[$i])
						{
							$match = $false
							break
						}
					}
					if ($match -and $bitsLeft -gt 0)
					{
						$mask = 0xFF - [math]::Pow(2, 8 - $bitsLeft) + 1
						$mask = [int]$mask
						if (($ipBytes[$bitsToCheck] -band $mask) -ne ($subnetBytes[$bitsToCheck] -band $mask))
						{
							$match = $false
						}
					}
					if ($match) { $found = $true; break }
				}
				catch { }
			}
			if ($found) { break }
		}
		if (-not $found -and $ipList.Count -gt 0)
		{
			$missingSubnetDCs += [PSCustomObject]@{
				Name	    = $dc.Name
				IPAddresses = $ipList -join ', '
			}
		}
	}
	
	if ($CountOnly)
	{
		return @($missingSubnetDCs).Count
	}
	else
	{
		return $missingSubnetDCs
	}
}

#Sample variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory



