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

<#
.SYNOPSIS
    Checks for user accounts with reversible password encryption enabled (S-Reversible security check).

.DESCRIPTION
    This function implements the S-Reversible security check to identify user accounts that have 
    reversible password encryption enabled. When this setting is enabled, passwords are stored 
    in a way that can be reversed to plaintext, creating a significant security vulnerability.
    
    The function uses LDAP filter (userAccountControl:1.2.840.113556.1.4.803:=128) to identify
    accounts with the reversible encryption flag set.

.PARAMETER OutputFormat
    Specifies the output format. Valid values are 'Object', 'Summary', 'Detailed'.
    Default is 'Object'.

.PARAMETER CountOnly
    If specified, returns only the count of affected accounts instead of detailed information.
    This parameter overrides the OutputFormat parameter.

.PARAMETER LogPath
    Optional path to write audit logs. If not specified, no logging is performed.

.PARAMETER Server
    Specifies the Active Directory server to query. If not specified, uses the default domain controller.

.EXAMPLE
    Test-ReversiblePasswordEncryption
    
    Returns all accounts with reversible password encryption in object format.

.EXAMPLE
    Test-ReversiblePasswordEncryption -CountOnly
    
    Returns only the count of accounts with reversible password encryption.

.EXAMPLE
    Test-ReversiblePasswordEncryption -OutputFormat Summary
    
    Returns a summary count of affected accounts.

.EXAMPLE
    Test-ReversiblePasswordEncryption -OutputFormat Detailed -LogPath "C:\Logs\AD-Security.log"
    
    Returns detailed information about affected accounts and logs results to specified file.

.NOTES
    Rule ID: S-Reversible
    Risk Level: Critical
    
    Remediation: Remove the "Store password using reversible encryption" flag from all affected 
    accounts. The cleartext password will be removed at the next password change.
    
    Security Impact: Accounts with reversible encryption can have their passwords extracted 
    in cleartext using DCSync attacks or by accessing the supplementalCredential attribute.

.LINK
    https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption
#>

#Test-reversubliePassword
function Test-ReversiblePasswordEncryption
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[ValidateSet('Object', 'Summary', 'Detailed')]
		[string]$OutputFormat = 'Object',
		[Parameter(Mandatory = $false)]
		[switch]$CountOnly,
		[Parameter(Mandatory = $false)]
		[string]$LogPath,
		[Parameter(Mandatory = $false)]
		[string]$Server
	)
	
	begin
	{
		Write-Verbose "Starting S-Reversible security check for reversible password encryption"
		
		# Initialize result object
		$result = @{
			RuleId		     = 'S-Reversible'
			RuleName		 = 'Reversible Password Encryption Check'
			Timestamp	     = Get-Date
			RiskLevel	     = 'Critical'
			AffectedAccounts = @()
			TotalCount	     = 0
			Status		     = 'Unknown'
			Remediation	     = 'Remove "Store password using reversible encryption" flag from affected accounts'
		}
		
		# LDAP filter to find accounts with reversible encryption (userAccountControl bit 128)
		$ldapFilter = "(userAccountControl:1.2.840.113556.1.4.803:=128)"
		
		# Properties to retrieve for Get-ADUser (minimal if CountOnly is specified)
		if ($CountOnly)
		{
			$properties = @('SamAccountName') # Minimal properties for count only
		}
		else
		{
			$properties = @(
				'SamAccountName',
				'UserPrincipalName',
				'DistinguishedName',
				'UserAccountControl',
				'Enabled',
				'LastLogonDate',
				'PasswordLastSet',
				'WhenCreated'
			)
		}
	}
	
	process
	{
		try
		{
			Write-Verbose "Executing LDAP query with filter: $ldapFilter"
			
			# Build Get-ADUser parameters
			$adParams = @{
				LDAPFilter = $ldapFilter
				Properties = $properties
			}
			
			if ($Server)
			{
				$adParams.Server = $Server
			}
			
			# Execute the query using Get-ADUser
			$accounts = Get-ADUser @adParams
			
			if ($accounts)
			{
				$accountCount = $accounts.Count
				Write-Warning "Found $accountCount account(s) with reversible password encryption enabled!"
				
				$result.TotalCount = $accountCount
				$result.Status = 'FAILED'
				
				# If CountOnly is specified, skip detailed processing
				if (-not $CountOnly)
				{
					foreach ($account in $accounts)
					{
						$accountInfo = [PSCustomObject]@{
							Name			   = $account.Name
							SamAccountName	   = $account.SamAccountName
							UserPrincipalName  = $account.UserPrincipalName
							DistinguishedName  = $account.DistinguishedName
							Enabled		       = $account.Enabled
							LastLogonDate	   = $account.LastLogonDate
							PasswordLastSet    = $account.PasswordLastSet
							WhenCreated	       = $account.WhenCreated
							UserAccountControl = $account.UserAccountControl
							RiskReason		   = 'Reversible password encryption enabled - password stored in cleartext'
						}
						
						$result.AffectedAccounts += $accountInfo
					}
				}
			}
			else
			{
				Write-Verbose "No accounts found with reversible password encryption"
				$result.Status = 'PASSED'
				$result.TotalCount = 0
			}
		}
		catch
		{
			Write-Error "Error executing reversible password encryption check: $($_.Exception.Message)"
			$result.Status = 'ERROR'
			$result.ErrorMessage = $_.Exception.Message
		}
	}
	
	end
	{
		# Log results if LogPath is specified
		if ($LogPath)
		{
			try
			{
				$logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - S-Reversible Check - Status: $($result.Status) - Affected Accounts: $($result.TotalCount)"
				Add-Content -Path $LogPath -Value $logEntry
				Write-Verbose "Results logged to: $LogPath"
			}
			catch
			{
				Write-Warning "Failed to write to log file: $($_.Exception.Message)"
			}
		}
		
		# Return results based on CountOnly parameter first, then OutputFormat
		if ($CountOnly)
		{
			return $result.TotalCount
		}
		
		switch ($OutputFormat)
		{
			'Summary' {
				return [PSCustomObject]@{
					RuleId			      = $result.RuleId
					Status			      = $result.Status
					TotalAffectedAccounts = $result.TotalCount
					RiskLevel			  = $result.RiskLevel
					Timestamp			  = $result.Timestamp
				}
			}
			
			'Detailed' {
				return $result
			}
			
			default {
				# 'Object'
				if ($result.AffectedAccounts.Count -gt 0)
				{
					return $result.AffectedAccounts
				}
				else
				{
					return [PSCustomObject]@{
						Status  = $result.Status
						Message = "No accounts found with reversible password encryption"
						RuleId  = $result.RuleId
					}
				}
			}
		}
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

#Golden Ticket age
<#
.SYNOPSIS
    Checks the password age of the Krbtgt account for Golden Ticket attack prevention (S-KrbtgtAge security check).

.DESCRIPTION
    This function implements a security check to verify the age of the Krbtgt account password.
    The Krbtgt account is used by the Kerberos Key Distribution Center (KDC) service to encrypt
    and sign Kerberos tickets. If compromised, attackers can create Golden Tickets that provide
    persistent domain access. Microsoft recommends changing the Krbtgt password regularly.
    
    The function checks both the primary Krbtgt account and any read-only domain controller
    (RODC) Krbtgt accounts (krbtgt_*).

.PARAMETER MaxPasswordAge
    Specifies the maximum acceptable password age in days. Default is 180 days.
    Microsoft recommends changing Krbtgt passwords at least every 180 days.

.PARAMETER OutputFormat
    Specifies the output format. Valid values are 'Object', 'Summary', 'Detailed'.
    Default is 'Object'.

.PARAMETER CountOnly
    If specified, returns only the count of Krbtgt accounts that exceed the maximum password age.

.PARAMETER AgeOnly
    If specified, returns only the password age in days as numeric values.
    For single Krbtgt account, returns a single integer. For multiple accounts, returns an array of integers.
    This parameter overrides CountOnly and OutputFormat parameters.

.PARAMETER LogPath
    Optional path to write audit logs. If not specified, no logging is performed.

.PARAMETER Server
    Specifies the Active Directory server to query. If not specified, uses the default domain controller.

.EXAMPLE
    Test-KrbtgtPasswordAge
    
    Checks if Krbtgt password is older than 180 days (default).

.EXAMPLE
    Test-KrbtgtPasswordAge -AgeOnly
    
    Returns only the password age in days as numeric value(s). Example output: 245

.EXAMPLE
    Test-KrbtgtPasswordAge -MaxPasswordAge 90
    
    Checks if Krbtgt password is older than 90 days.

.EXAMPLE
    Test-KrbtgtPasswordAge -OutputFormat Summary -MaxPasswordAge 120
    
    Returns a summary of Krbtgt accounts with passwords older than 120 days.

.EXAMPLE
    Test-KrbtgtPasswordAge -CountOnly
    
    Returns only the count of Krbtgt accounts that need password rotation.

.EXAMPLE
    Test-KrbtgtPasswordAge -OutputFormat Detailed -LogPath "C:\Logs\AD-Security.log"
    
    Returns detailed information and logs results to specified file.

.NOTES
    Rule ID: S-KrbtgtAge
    Risk Level: High
    
    Remediation: 
    1. Reset the Krbtgt password using: Reset-KrbtgtAccountPassword or similar tools
    2. Reset twice (with replication time between) to invalidate all existing tickets
    3. Implement regular password rotation schedule (every 180 days maximum)
    4. Monitor for any service disruptions after password reset
    
    Security Impact: 
    - Old Krbtgt passwords allow Golden Ticket attacks to persist
    - Attackers with compromised Krbtgt hash can create persistent backdoors
    - Golden Tickets can bypass most security controls and provide domain admin access

.LINK
    https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password
    https://www.microsoft.com/en-us/download/details.aspx?id=53486
#>

function Test-KrbtgtPasswordAge
{
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[int]$MaxPasswordAge = 180,
		[Parameter(Mandatory = $false)]
		[ValidateSet('Object', 'Summary', 'Detailed')]
		[string]$OutputFormat = 'Object',
		[Parameter(Mandatory = $false)]
		[switch]$CountOnly,
		[Parameter(Mandatory = $false)]
		[switch]$AgeOnly,
		[Parameter(Mandatory = $false)]
		[string]$LogPath,
		[Parameter(Mandatory = $false)]
		[string]$Server
	)
	
	begin
	{
		Write-Verbose "Starting S-KrbtgtAge security check for Krbtgt password age"
		
		# Initialize result object
		$result = @{
			RuleId			   = 'S-KrbtgtAge'
			RuleName		   = 'Krbtgt Password Age Check'
			Timestamp		   = Get-Date
			RiskLevel		   = 'High'
			MaxPasswordAgeDays = $MaxPasswordAge
			AffectedAccounts   = @()
			TotalCount		   = 0
			Status			   = 'Unknown'
			Remediation	       = 'Reset Krbtgt password using proper procedures (reset twice with replication time)'
		}
		
		# Current date for age calculation
		$currentDate = Get-Date
		
		# LDAP filter to find Krbtgt accounts (including RODC accounts)
		$ldapFilter = "(|(samAccountName=krbtgt)(samAccountName=krbtgt_*))"
		
		# Properties to retrieve (minimal for AgeOnly or CountOnly)
		if ($AgeOnly -or $CountOnly)
		{
			$properties = @('SamAccountName', 'PasswordLastSet')
		}
		else
		{
			$properties = @(
				'SamAccountName',
				'DistinguishedName',
				'PasswordLastSet',
				'WhenCreated',
				'UserAccountControl',
				'Enabled',
				'Description'
			)
		}
	}
	
	process
	{
		try
		{
			Write-Verbose "Searching for Krbtgt accounts with filter: $ldapFilter"
			
			# Build Get-ADUser parameters
			$adParams = @{
				LDAPFilter = $ldapFilter
				Properties = $properties
			}
			
			if ($Server)
			{
				$adParams.Server = $Server
			}
			
			# Execute the query
			$krbtgtAccounts = Get-ADUser @adParams
			
			if ($krbtgtAccounts)
			{
				Write-Verbose "Found $($krbtgtAccounts.Count) Krbtgt account(s)"
				
				# If AgeOnly is specified, return just the numeric ages
				if ($AgeOnly)
				{
					$ageValues = @()
					foreach ($account in $krbtgtAccounts)
					{
						$passwordLastSet = $account.PasswordLastSet
						
						if ($passwordLastSet)
						{
							$passwordAge = ($currentDate - $passwordLastSet).Days
							$ageValues += $passwordAge
						}
						else
						{
							# Return -1 for unknown password dates
							$ageValues += -1
						}
					}
					
					# Return single value if only one account, array if multiple
					if ($ageValues.Count -eq 1)
					{
						return $ageValues[0]
					}
					else
					{
						return $ageValues
					}
				}
				
				foreach ($account in $krbtgtAccounts)
				{
					$passwordLastSet = $account.PasswordLastSet
					
					if ($passwordLastSet)
					{
						$passwordAge = ($currentDate - $passwordLastSet).Days
						$isExpired = $passwordAge -gt $MaxPasswordAge
						
						if ($isExpired)
						{
							Write-Warning "Krbtgt account '$($account.SamAccountName)' password is $passwordAge days old (exceeds $MaxPasswordAge days)"
							
							if (-not $CountOnly)
							{
								$accountInfo = [PSCustomObject]@{
									SamAccountName	   = $account.SamAccountName
									DistinguishedName  = $account.DistinguishedName
									PasswordLastSet    = $passwordLastSet
									PasswordAgeDays    = $passwordAge
									MaxPasswordAgeDays = $MaxPasswordAge
									DaysOverdue	       = $passwordAge - $MaxPasswordAge
									WhenCreated	       = $account.WhenCreated
									Enabled		       = $account.Enabled
									Description	       = $account.Description
									UserAccountControl = $account.UserAccountControl
									RiskLevel		   = if ($passwordAge -gt 365) { 'Critical' }
									elseif ($passwordAge -gt 270) { 'High' }
									else { 'Medium' }
									RiskReason		   = "Krbtgt password is $passwordAge days old - enables Golden Ticket attacks"
									AccountType	       = if ($account.SamAccountName -eq 'krbtgt') { 'Primary KDC' } else { 'RODC KDC' }
								}
								
								$result.AffectedAccounts += $accountInfo
							}
							
							$result.TotalCount++
						}
						else
						{
							Write-Verbose "Krbtgt account '$($account.SamAccountName)' password age is acceptable ($passwordAge days)"
						}
					}
					else
					{
						Write-Warning "Krbtgt account '$($account.SamAccountName)' has no password set date - this is highly unusual!"
						
						if (-not $CountOnly)
						{
							$accountInfo = [PSCustomObject]@{
								SamAccountName	   = $account.SamAccountName
								DistinguishedName  = $account.DistinguishedName
								PasswordLastSet    = $null
								PasswordAgeDays    = 'Unknown'
								MaxPasswordAgeDays = $MaxPasswordAge
								DaysOverdue	       = 'Unknown'
								WhenCreated	       = $account.WhenCreated
								Enabled		       = $account.Enabled
								Description	       = $account.Description
								UserAccountControl = $account.UserAccountControl
								RiskLevel		   = 'Critical'
								RiskReason		   = "Krbtgt password last set date is unknown - immediate investigation required"
								AccountType	       = if ($account.SamAccountName -eq 'krbtgt') { 'Primary KDC' } else { 'RODC KDC' }
							}
							
							$result.AffectedAccounts += $accountInfo
						}
						
						$result.TotalCount++
					}
				}
				
				if ($result.TotalCount -gt 0)
				{
					$result.Status = 'FAILED'
					# Adjust overall risk level based on findings
					if ($result.AffectedAccounts | Where-Object { $_.RiskLevel -eq 'Critical' })
					{
						$result.RiskLevel = 'Critical'
					}
				}
				else
				{
					$result.Status = 'PASSED'
					Write-Verbose "All Krbtgt accounts have acceptable password age"
				}
			}
			else
			{
				Write-Error "No Krbtgt accounts found - this indicates a serious Active Directory issue!"
				$result.Status = 'ERROR'
				$result.ErrorMessage = "No Krbtgt accounts found in domain"
			}
		}
		catch
		{
			Write-Error "Error executing Krbtgt password age check: $($_.Exception.Message)"
			$result.Status = 'ERROR'
			$result.ErrorMessage = $_.Exception.Message
		}
	}
	
	end
	{
		# Log results if LogPath is specified (skip for AgeOnly)
		if ($LogPath -and -not $AgeOnly)
		{
			try
			{
				$logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - S-KrbtgtAge Check - Status: $($result.Status) - Aged Accounts: $($result.TotalCount) - Max Age: $MaxPasswordAge days"
				Add-Content -Path $LogPath -Value $logEntry
				Write-Verbose "Results logged to: $LogPath"
			}
			catch
			{
				Write-Warning "Failed to write to log file: $($_.Exception.Message)"
			}
		}
		
		# Return results based on parameter precedence: AgeOnly > CountOnly > OutputFormat
		if ($AgeOnly)
		{
			# Already returned in the process block
			return
		}
		
		if ($CountOnly)
		{
			return $result.TotalCount
		}
		
		switch ($OutputFormat)
		{
			'Summary' {
				return [PSCustomObject]@{
					RuleId			   = $result.RuleId
					Status			   = $result.Status
					TotalAgedAccounts  = $result.TotalCount
					MaxPasswordAgeDays = $result.MaxPasswordAgeDays
					RiskLevel		   = $result.RiskLevel
					Timestamp		   = $result.Timestamp
					RecommendedAction  = if ($result.TotalCount -gt 0) { 'Reset Krbtgt password immediately' } else { 'No action required' }
				}
			}
			
			'Detailed' {
				return $result
			}
			
			default {
				# 'Object'
				if ($result.AffectedAccounts.Count -gt 0)
				{
					return $result.AffectedAccounts
				}
				else
				{
					return [PSCustomObject]@{
						Status																		      = $result.Status
						Message																		      = if ($result.Status -eq 'PASSED')
						{
							"All Krbtgt accounts have acceptable password age (within $MaxPasswordAge days)"
						} else {
							$result.ErrorMessage
						}
						RuleId																		      = $result.RuleId
						MaxPasswordAgeDays															      = $result.MaxPasswordAgeDays
					}
				}
			}
		}
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

#S-Reversible: Check for user accounts with reversible password encryption
function Test-ReversiblePasswordEncryption
{
<#
	.SYNOPSIS
		Detects user accounts with reversible password encryption enabled.

	.DESCRIPTION
		This function identifies user accounts that have reversible password encryption enabled,
		which represents a critical security vulnerability. When reversible encryption is enabled,
		passwords are stored in a way that allows them to be recovered in cleartext, making
		accounts vulnerable to DCSync attacks and password recovery.

	.PARAMETER CountOnly
		When specified, returns only the count of accounts with reversible encryption instead
		of detailed account information.

	.PARAMETER IncludeDisabled
		When specified, includes disabled accounts in the results. By default, only enabled
		accounts are checked.

	.PARAMETER OutputFormat
		Specifies the output format. Valid values are 'Object', 'Summary', 'Detailed'.
		- Object: Returns PowerShell objects with account details
		- Summary: Returns a brief summary with count and risk level
		- Detailed: Returns comprehensive information including remediation steps

	.OUTPUTS
		PSCustomObject or Int32 (when CountOnly is specified)
		Returns account details, count, and risk assessment information.

	.EXAMPLE
		Test-ReversiblePasswordEncryption
		
		Returns all enabled user accounts with reversible password encryption.

	.EXAMPLE
		Test-ReversiblePasswordEncryption -CountOnly
		
		Returns only the count of accounts with reversible encryption.

	.EXAMPLE
		Test-ReversiblePasswordEncryption -OutputFormat Summary
		
		Returns a summary with count and risk level assessment.

	.EXAMPLE
		Test-ReversiblePasswordEncryption -IncludeDisabled -OutputFormat Detailed
		
		Returns detailed information including disabled accounts and remediation steps.

	.NOTES
		Rule ID: S-Reversible
		Risk Level: CRITICAL
		
		SECURITY CONTEXT:
		Reversible password encryption is a critical security vulnerability that allows
		passwords to be recovered in cleartext. This makes accounts vulnerable to:
		- DCSync attacks
		- Password recovery by attackers with appropriate privileges
		- Lateral movement within the network
		
		REMEDIATION STEPS:
		1. Identify all accounts with reversible encryption enabled
		2. For each account, disable reversible encryption:
		   - In ADUC: Uncheck "Store password using reversible encryption"
		   - PowerShell: Set-ADUser -Identity <username> -AllowReversiblePasswordEncryption $false
		3. Force password reset for affected accounts to ensure passwords are re-encrypted
		4. Implement Group Policy to prevent future use of reversible encryption
		5. Monitor for any new accounts with this setting enabled
		
		DETECTION METHOD:
		Uses LDAP filter (userAccountControl:1.2.840.113556.1.4.803:=128) to identify
		accounts with the ENCRYPTED_TEXT_PWD_ALLOWED flag (0x80/128) set.

	.LINK
		https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption
#>
	param (
		[Parameter(Mandatory = $false)]
		[switch]$CountOnly,
		[Parameter(Mandatory = $false)]
		[switch]$IncludeDisabled,
		[Parameter(Mandatory = $false)]
		[ValidateSet('Object', 'Summary', 'Detailed')]
		[string]$OutputFormat = 'Object'
	)
	
	try
	{
		Write-Verbose "Starting S-Reversible security check for reversible password encryption"
		
		# Build the LDAP filter for reversible encryption
		# UserAccountControl flag 128 (0x80) = ENCRYPTED_TEXT_PWD_ALLOWED
		$ldapFilter = "(userAccountControl:1.2.840.113556.1.4.803:=128)"
		
		# Add filter to exclude disabled accounts unless specifically requested
		if (-not $IncludeDisabled)
		{
			# Combine with filter to exclude disabled accounts (userAccountControl flag 2)
			$ldapFilter = "(&(userAccountControl:1.2.840.113556.1.4.803:=128)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
		}
		
		Write-Verbose "Using LDAP filter: $ldapFilter"
		
		# Query AD for users with reversible encryption
		$reversibleUsers = Get-ADUser -LDAPFilter $ldapFilter -Properties samAccountName, DisplayName, UserAccountControl, Enabled, whenCreated, PasswordLastSet, LastLogonDate
		
		$userCount = @($reversibleUsers).Count
		Write-Verbose "Found $userCount accounts with reversible password encryption"
		
		# Return count only if requested
		if ($CountOnly)
		{
			return $userCount
		}
		
		# Determine risk level based on count
		$riskLevel = switch ($userCount)
		{
			0 { "LOW" }
			{ $_ -ge 1 -and $_ -le 5 } { "HIGH" }
			{ $_ -ge 6 -and $_ -le 20 } { "CRITICAL" }
			{ $_ -gt 20 } { "EXTREME" }
			default { "UNKNOWN" }
		}
		
		# Process results based on output format
		switch ($OutputFormat)
		{
			'Summary' {
				return [PSCustomObject]@{
					RuleID = "S-Reversible"
					Description = "User accounts with reversible password encryption"
					AccountCount = $userCount
					RiskLevel = $riskLevel
					Status = if ($userCount -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
					Recommendation = if ($userCount -gt 0) { "Immediately disable reversible encryption and reset passwords" } else { "No action required" }
				}
			}
			'Detailed' {
				$accountDetails = $reversibleUsers | ForEach-Object {
					[PSCustomObject]@{
						samAccountName = $_.samAccountName
						DisplayName = $_.DisplayName
						Enabled = $_.Enabled
						whenCreated = $_.whenCreated
						PasswordLastSet = $_.PasswordLastSet
						LastLogonDate = $_.LastLogonDate
						UserAccountControl = $_.UserAccountControl
						RiskLevel = "CRITICAL"
						RemediationCommand = "Set-ADUser -Identity '$($_.samAccountName)' -AllowReversiblePasswordEncryption `$false"
					}
				}
				
				return [PSCustomObject]@{
					RuleID = "S-Reversible"
					Description = "User accounts with reversible password encryption"
					AccountCount = $userCount
					RiskLevel = $riskLevel
					Status = if ($userCount -eq 0) { "COMPLIANT" } else { "NON-COMPLIANT" }
					AffectedAccounts = $accountDetails
					RemediationSteps = @(
						"1. Disable reversible encryption for each account",
						"2. Force password reset for all affected accounts",
						"3. Implement Group Policy to prevent future use",
						"4. Monitor for new accounts with this setting"
					)
					SecurityImpact = "CRITICAL - Passwords can be recovered in cleartext, enabling DCSync attacks and lateral movement"
				}
			}
			default { # 'Object'
				return $reversibleUsers | Select-Object samAccountName, DisplayName, Enabled, whenCreated, PasswordLastSet, LastLogonDate, UserAccountControl
			}
		}
	}
	catch
	{
		Write-Error "Error during S-Reversible check: $($_.Exception.Message)"
		if ($CountOnly)
		{
			return -1
		}
		else
		{
			return [PSCustomObject]@{
				RuleID = "S-Reversible"
				Error = $_.Exception.Message
				Status = "ERROR"
			}
		}
	}
}

#Sample variable that provides the location of the script
[string]$ScriptDirectory = Get-ScriptDirectory



