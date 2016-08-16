#=======================================================================#
#
# Author:				Collin Chaffin
# Last Modified:		03-13-2016 12:00PM
# Filename:				psFitb1t.psm1
#
#
# Changelog:
#
#	v 1.0.0.1	:	03-13-2016	:	Initial release
#	v 1.0.0.2	:	03-30-2016	:	Added Get-HRmonth function
#   v 1.0.0.3   :   08-16-2016  :   Added Get-HRMin, Get-HRMax, Get-HRAVg cmdlets
#
# Notes:
#
#	This module utilizes personal Fitbit's user-specific API
#	information to perform OAuth connection to Fitbit and submit the
#	request for your heart rate data for any 24 hour period.
#
#
# Installation Instructions:
#
#	Run the MSI installer or, if installing manually, copy the
#	psFitb1t.psm1 and psFitb1t.psd files to:
#	"%PSModulePath%psFitb1t"
#
#	HINT: To manually create the module folder prior to copying:
#	mkdir "%PSModulePath%psFitb1t"
#
#	Once installed/copied, open Windows Powershell and execute:
#	Import-Module psFitb1t
#
#	Store your Fitbit API information by executing:
#	Set-FitbitOAuthTokens
#
#	If you have gotten this far, you should be able to query your
#	first date by executing:
#	Get-HRData -QueryDate "2016-01-01"
#
# Verification:
#
#	Check "%PSModulePath%psFitb1t\Logs" folder for a daily rotating log.
#	Example log for successful query:
#
#	03/13/2016 12:00:00 :: [INFO] :: START  - Get-HRdata function execution
#	03/13/2016 12:00:00 :: [INFO] :: START  - Connect-OAuthFitbit function execution
#	03/13/2016 12:00:00 :: [INFO] :: START  - Loading DOTNET assemblies
#	03/13/2016 12:00:00 :: [INFO] :: FINISH - Loading DOTNET assemblies
#	03/13/2016 12:00:00 :: [INFO] :: START  - Retrieving Fitbit API settings from registry
#	03/13/2016 12:00:00 :: [INFO] :: FINISH - Retrieving Fitbit API settings from registry
#	03/13/2016 12:00:01 :: [INFO] :: FINISH - Connect-OAuthFitbit function execution
#	03/13/2016 12:00:01 :: [INFO] :: START  - Sending HTTP POST via REST to Fitbit
#	03/04/2016 12:00:44 :: [INFO] :: FINISH - Sending HTTP POST via REST to Fitbit
#	03/04/2016 12:00:44 :: [INFO] :: FINISH - Get-HRdata function execution
#
#=======================================================================#


#region Globals

#########################################################################
# 							Global Variables							#
#########################################################################

# General Variables
# Disable psFitb1tDebugging for zero output and logging
$psFitb1tDebugging = $true
$psFitb1tLogging = $true
$Script:psFitb1tScope = "activity%20heartrate%20location%20nutrition%20profile%20settings%20sleep%20social%20weight"
$Script:psFitb1tTokenAge = "2592000"

#You should only have to change this redirect URL if you did not follow the directions and set it to this predetermined value:
$Script:psFitb1tRedirectURL = "https://localhost/psfitb1t"
$Script:psFitb1tHRQueryDate = ""
$Script:psFitb1tTokenReturnedAge = ""
$Script:psFitb1tAuthCode = ""

#Auth URL First
#$Script:psFitb1tAuthorizeUrl = "https://www.fitbit.com/oauth2/authorize?response_type=token&client_id=$psFitb1tClientID&redirect_uri=$psFitb1tRedirectURL&scope=$psFitb1tScope&expires_in=$psFitb1tTokenAge"

# Paths
$Script:psFitb1tInvocationPath = $([System.IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Definition) + "\")
$Script:psFitb1tLogPath = $($psFitb1tInvocationPath) + "Logs\"
# Override this with a static manual path, if so desired or it defaults to \Logs folder in Module location

#########################################################################

#endregion

#region Functions

#########################################################################
# 								Functions								#
#########################################################################


function Connect-OAuthFitbit
{
	<#
	.SYNOPSIS
		This function utilizes personal Fitbit's user-specific API information to perform
		OAuth connection to Fitbit and set up the final OAuth string needed to then retrieve
		24hrs of HR data using the REST API.
		
	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function utilizes personal Fitbit's user-specific API
						information to perform OAuth connection to Fitbit.		
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
	param	(					
	)	
	BEGIN
	{		
		(Write-Status -Message "START  - Connect-OAuthFitbit function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
		try
		{
			(Write-Status -Message "START  - Loading DOTNET assemblies" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			[Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null
			[Reflection.Assembly]::LoadWithPartialName("System.Net") | Out-Null
			[Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null
			(Write-Status -Message "FINISH - Loading DOTNET assemblies" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
		}
		catch
		{
			Throw $("ERROR OCCURRED WHILE LOADING REQUIRED DOTNET ASSEMBLIES " + $_.Exception.Message)			
		}
		
		# Retrieve required user-specific Fitbit API info from registry
		try
		{			
			if ($((Test-Path -Path HKCU:\Software\psFitb1t) -eq $false) `
			   -or $((Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tClientID") -eq $null) `
				-or $((Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tRedirectURL") -eq $null)				
			   )
			{
				(Write-Status -Message "Fitbit API settings not found - prompting operator" -Status "WARNING" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
				# Call Set-FitbitOAuthTokens function to prompt for credentials and store them
				Set-FitbitOAuthTokens
			}
			else
			{
				(Write-Status -Message "START  - Retrieving Fitbit API settings from registry" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
				$Script:psFitb1tClientID				= (Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tClientID")
				$Script:psFitb1tRedirectURL			= (Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tRedirectURL")				
				$Script:psFitb1tTokenReturnedAge 	= (Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tTokenAge")
				$Script:psFitb1tAuthToken 		= (Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tAuthToken")
				(Write-Status -Message "FINISH - Retrieving Fitbit API settings from registry" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			}			
		}
		catch
		{
			Throw $("ERROR OCCURRED WHILE LOADING REQUIRED FITBIT API INFORMATION " + $_.Exception.Message)
		}
	}
	PROCESS
	{
		try
		{
			# Create a custom PSObject to store all require oAuth info and simply pass a single object to helper functions			
			$objOAuth = @()
			$objOAuth = New-Object -TypeName PSObject
			$objOAuth | Add-Member -Name 'client_id' -Value $($psFitb1tClientID) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'redirect_uri' -Value $($psFitb1tRedirectURL) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'scope' -Value $($psFitb1tScope) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'expires_in' -Value $($psFitb1tTokenAge) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'token_remaining' -Value $($psFitb1tTokenReturnedAge) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'date' -Value $($psFitb1tHRQueryDate) -MemberType NoteProperty -Force
			$objOAuth | Add-Member -Name 'access_token' -Value $($psFitb1tAuthToken) -MemberType NoteProperty -Force
						
			#Do we have a good token already? Check registry			
			if ($($Script:psFitb1tTokenReturnedAge) -and  $(Test-Date -inputDate $Script:psFitb1tTokenReturnedAge) -and $( [DateTime]$(get-date ([System.DateTime]::Now) -Format s) -lt [DateTime]$(Get-Date($psFitb1tTokenReturnedAge)) )  )
			{
				write-verbose "Token Okay"
				[string]$oAuthRequestString = $psFitb1tAuthToken
			}
			else
			{
				write-verbose "Token Expired $($Script:psFitb1tTokenReturnedAge)"
				# Finally, generate the final OAuth request string with all the above generated information passing one single custom PSObject
				[string]$oAuthRequestString = (Get-FitbitOAuthToken -objOAuth $objOAuth)				
			}			
			
			# Return the one single oAuth request POST string to hand back to calling function (tweet or direct message) to POST it
			Return $oAuthRequestString;
		}
		catch
		{
			Throw $("ERROR OCCURRED WHILE BUILDING OAUTH REQUEST " + $_.Exception.Message)
		}
	}
	END
	{
		(Write-Status -Message "FINISH - Connect-OAuthFitbit function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
}



function Get-FitbitOAuthToken
{
	<#
	.SYNOPSIS
		Generate a new Fitbit oAuth2 token or used stored

	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function generates a new Fitbit oAuth2 token or used stored
		
	.PARAMETER objOAuth
		[PSObject] Custom PSObject containing all required OAuth information
	
	.EXAMPLE
		$oAuthSignature = (Get-FitbitOAuthToken -objOAuth $objOAuth)
	
		$oAuthSignature
		ptUHUftvP0l635876583ygrgg346JQoJ+7yBa//uZcE=
	#>
	[CmdletBinding()]
	[OutputType([String])]
	param (
		[Parameter(Position = 0, Mandatory = $true)]		
			[ValidateNotNullOrEmpty()]
			[PSObject]
			$objOAuth
	)
	BEGIN
	{
		(Write-Status -Message "START  - Get-FitbitOAuthToken function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
	PROCESS
	{
		try
		{
			(Write-Status -Message "START  - Building OAuth signature" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			
			# Make GET request to have user authorize and parse for token returned - run with -VERBOSE switch to view the string actually being sent!
			$Script:psFitb1tAuthorizeUrl = "https://www.fitbit.com/oauth2/authorize?response_type=token&client_id=$psFitb1tClientID&redirect_uri=$psFitb1tRedirectURL&scope=$psFitb1tScope&expires_in=$psFitb1tTokenAge"
			Write-Verbose "Sending $($psFitb1tAuthorizeUrl)"
			
			Add-Type -AssemblyName System.Windows.Forms
			$form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width = 440; Height = 640 }
			$browser = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width = 420; Height = 600; Url = $psFitb1tAuthorizeUrl }
			
			$onDocumentCompleted = {
				
				$myurl = $browser.Url.AbsoluteUri
				if ($browser.Url.AbsoluteUri -match "access_token=([^&]*)")
				{
					#Get the magic token
					$Script:psFitb1tAuthCode = $Matches[1]
															
					if ($browser.Url.AbsoluteUri -match "expires_in=([^&]*)")
					{
						$Script:psFitb1tTokenReturnedAge = $(get-date ([System.DateTime]::Now).AddSeconds([int]$Matches[1]) -Format s)
						Write-Verbose "Token expires: $($Script:psFitb1tTokenReturnedAge)"
						
						#write $Script:psFitb1tTokenReturnedAge to registry
						New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tTokenAge" -value "$Script:psFitb1tTokenReturnedAge" -Force | out-null
						
						#write $Script:psFitb1tAuthToken to registry
						New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tAuthToken" -value "$Script:psFitb1tAuthCode" -Force | out-null												
						
						$form.Close()
					}
					#Close it
					$form.Close()
				}				
				elseif ($browser.Url.AbsoluteUri -match "error=")
				{
					$form.Close()
				}
			}			
			
			$browser.add_DocumentCompleted($onDocumentCompleted)			
			$form.Controls.Add($browser)
			$null = $form.ShowDialog()
			
			Write-Verbose "Auth Code is: $($psFitb1tAuthCode)"			
			
			(Write-Status -Message "FINISH - Building OAuth signature" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			
			return $psFitb1tAuthCode;
		}
		catch
		{
			Throw $("ERROR OCCURRED GENERATING NEW OAUTH SIGNATURE " + $_.Exception.Message)
		}		
	}
	END
	{
		(Write-Status -Message "FINISH - Get-FitbitOAuthToken function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
}


function Test-Date
{
	<#
	.SYNOPSIS
		Test if date is valid

	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function tests if date is valid

	.PARAMETER inputDate
		[String] Date STRING to test with different possible formats
	
	.EXAMPLE
		Test-Date -inputDate "2016-03-29T03:23:28"			
	#>
	param
	(
		[Parameter(Mandatory = $true)]
		$inputDate
	)	
	(($inputDate -as [DateTime]) -ne $null)
}


function Write-Status
{
	<#
	.SYNOPSIS
		Write a status message to console and log if debugging

	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function writes a status message out to console
						appending exact time/date of command execution and will
						optionally write to daily log

	.PARAMETER Message
		[String] Message to write
			
	.PARAMETER Status
		[String] Status code string
	
	.PARAMETER Debugging
		[Bool] If this switch is true then output debugging to console
	
	.EXAMPLE
		Write-Status -Message "Action completed successfully" -Status "SUCCESS" -Debugging $debugging
	
		03/13/2016 12:00:00 :: [SUCCESS] :: Action completed successfully	
	#>
	[CmdletBinding()]
	[OutputType([System.String])]
	param (
		[Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]		
			[System.String]
			$Message,		
		[Parameter(Mandatory = $false)]
			[System.String]
			$Status = "INFO",
		[Parameter(Mandatory = $false)]
			[Switch]
			$Debugging,
		[Parameter(Mandatory = $false)]
			[Switch]
			$Logging,
		[Parameter(Mandatory = $false)]
			[System.String]
			$LogPath = $(($psFitb1tInvocationPath) + "Logs\")
	)
	BEGIN
	{
		try
		{	
			# Do not do anything unless global script debugging is true
			If ($Debugging -eq $true)
			{
				# Set up variables and log file/path
				[String]$statusTime = (Get-Date -Format "MM/dd/yyyy HH:mm:ss")
				
				# If -Logging passed, set up logging a a DAILY log file (change path in globals at top of script)
				if ($Logging -eq $true)
				{
					If (!(Test-Path $psFitb1tLogPath)) { New-Item -ItemType Directory -Force -Path ($psFitb1tLogPath) | Out-Null }
					[String]$logFileDate = (Get-Date -Format "MM-dd-yyyy")
					[String]$logFile = $($psFitb1tLogPath) + "psFitb1t-" + $logFileDate + ".log"
				}
			}				
		}
		catch
		{
			Throw $("ERROR OCCURRED WHILE WRITING OUTPUT " + $_.Exception.Message)
		}
	}
	PROCESS
	{
		try
		{
			# Do not do anything unless global script debugging is true
			If ($Debugging -eq $true)
			{
				# Ensure custom status is always uppercase
				$Status = $Status.ToUpper()
				
				# Format output message
				$Message = "$statusTime :: [$Status] :: $Message"
				
				# Write out to console
				Write-Host $Message -ForegroundColor Cyan
					
				# If -Logging passed, set up logging a a DAILY log file (change path in globals at top of script)
				if ($Logging -eq $true)
				{				
					Add-Content -Path $logFile -Value ($Message)
				}
			}
		}
		catch
		{
			Throw $("ERROR OCCURRED WRITING STATUS" + $_.Exception.Message)
		}
	}
	END
	{
	}
}

Function Set-FitbitOAuthTokens
{
  <#
	.SYNOPSIS
		Stores required Fitbit API OAuth settings providing both GUI wizard and
		command-line options
		

	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	This function stores the required Fitbit API settings
						provided by the operator interactively into the HKCU
						registry hive for subsequent sessions providing both
						GUI wizard and command-line options

	.PARAMETER Force
		[Switch] Clear existing stored Fitbit API information and repopulate

	.PARAMETER psFitb1tClientID
		[String] Fitbit Client ID

	.PARAMETER psFitb1tRedirectURL
		[String] Fitbit Redirection URL

	.PARAMETER psFitb1tHRQueryDate
		[String] Fitbit Last Query Date

	.PARAMETER psFitb1tTokenAge
		[String] Fitbit Access Token Expiration Datetime

	.EXAMPLE
		Set-FitbitOAuthTokens

		If Fitbit API settings are not found in the registry, prompt the operator
		interactively via a GUI wizard to provide and open the Fitbit API webpage
		to assist operator in locating their user-specific Fitbit application information
		
		NOTE: Only missing information will be requested via wizard interface

	.EXAMPLE
		Set-FitbitOAuthTokens -Force

		Remove existing Fitbit API information from registry and repopulate via
		GUI wizard

	.EXAMPLE
		Set-FitbitOAuthTokens -Force -psFitb1tClientID "01234567890"

		Remove existing Fitbit API information from registry and repopulate via
		automatically detected "command-line" mode.  In this case because all
		four required pieces of information were not provided, the missing three
		will be interactively prompted but via standard commandline text prompting
	#>
	[CmdletBinding(DefaultParameterSetName = 'Wizard')]
	[OutputType([System.String])]
	param
	(
		[Parameter(ParameterSetName = 'CmdLine', Mandatory = $false)]
		[Parameter(ParameterSetName = 'Wizard', Mandatory = $false)]
			[Switch]
			$Force,
		[Parameter(ParameterSetName = 'CmdLine', Mandatory = $true, HelpMessage = 'Please enter your Fitbit application CLIENT ID:')]
			[ValidateNotNullOrEmpty()]
			[System.String]
			$psFitb1tClientID,
		[Parameter(ParameterSetName = 'CmdLine', Mandatory = $false, HelpMessage = 'Please enter your Fitbit application REDIRECT URL:')]
			[ValidateNotNullOrEmpty()]
			[System.String]
			$psFitb1tRedirectURL = $Script:psFitb1tRedirectURL
	)
	BEGIN
	{
		(Write-Status -Message "START  - Set-FitbitOAuthTokens function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
	PROCESS
	{
		# If we were passed -Force switch
		if ($Force.IsPresent)
		{
			try
			{				
					# Force switch used, remove/clear all stored API info and drop to either wizard or cmdline to repopulate
					if ($((Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tClientID") -ne $null)) { Remove-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tClientID" }
					if ($((Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tRedirectURL") -ne $null)) { Remove-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tRedirectURL" }
					if ($((Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tHRQueryDate") -ne $null)) { Remove-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tHRQueryDate" }
					if ($((Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tTokenAge") -ne $null)) { Remove-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tTokenAge" }
					if ($((Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tAuthToken") -ne $null)) { Remove-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tAuthToken" }
				
			}
			catch
			{
				Throw $("ERROR OCCURRED CLEARING FITBIT API INFORMATION FROM REGISTRY " + $_.Exception.Message)
			}
		}
		
		# (Re)Populate the registry with 4 pieces of required Fitbit OAuth info
		try
		{	
			# If any single piece of info is missing, start the process
			if ($((Test-Path -Path HKCU:\Software\psFitb1t) -eq $false) `
			   -or $((Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tClientID") -eq $null) `
			   -or $((Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tRedirectURL") -eq $null)			   
			   )
			{
				Write-Host "`nPlease configure your personal Fitbit application from which you must store the following pieces of information:`n`n""Client ID""`n""Redirect URL""`n`nOpening default browser to: https://dev.fitbit.com" -ForegroundColor Yellow
				
				Start-Process "https://dev.fitbit.com/"
				
				# Entire reg key is missing so create it
				if (!(Test-Path -Path HKCU:\Software\psFitb1t))
				{
					(Write-Status -Message "START  - psFitb1t registry key creation" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
					New-Item -Path HKCU:\Software -Name psFitb1t | out-null
					(Write-Status -Message "FINISH - psFitb1t registry key creation" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
				}
				
				Switch ($PSCmdlet.ParameterSetName)
				{
					'Wizard'
					{
						# Now that we are sure reg key exists, call the wizard form and prompt only for missing value(s)
						# NOTE: If reg key exists and only 2 pieces of info are missing, operator only receives a wizard with 2 pages with 4 being all info missing
						Call-psFitb1t-API_psf | Out-Null
					}
					'CmdLine'
					{
						if (!$psFitb1tClientID)
						{
							Write-Host "`n`nEnter Fitbit Client ID:" -ForegroundColor Yellow -NoNewline
							$psFitb1tClientID = Read-Host							
							if ($psFitb1tClientID) { New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tClientID" -value "$psFitb1tClientID" | out-null }
						}
						else
						{
							New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tClientID" -value "$psFitb1tClientID" | out-null
						}
						if (! $psFitb1tRedirectURL)
						{
							Write-Host "Enter Fitbit Redirect URL:" -ForegroundColor Yellow -NoNewline
							$psFitb1tRedirectURL = Read-Host
							if ($psFitb1tRedirectURL) { New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tRedirectURL" -value "$psFitb1tRedirectURL" | out-null }
						}
						else
						{
							New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tRedirectURL" -value "$psFitb1tRedirectURL" | out-null
						}
						
					}
				}
			}
		}
		catch
		{
			Throw $("ERROR OCCURRED WRITING FITBIT API INFORMATION TO REGISTRY " + $_.Exception.Message)
		}
		finally
		{
			# Now that the reg values are present regardless of method, read back in the values and set our globals
			$Script:psFitb1tClientID = (Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tClientID")
			$Script:psFitb1tRedirectURL = (Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tRedirectURL")
			
		}
	}
	END
	{
		(Write-Status -Message "FINISH - Set-FitbitOAuthTokens function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
	
}



function Get-HRdata
{
	<#
	.SYNOPSIS
		Sends a Fitbit Tweet
	
	.DESCRIPTION
		Author:  		Collin Chaffin
		Description:	Sends a request for 24hrs of HR data using OAuth and REST							
	
	.PARAMETER QueryDate
		The single 24hr Date to retrieve HR data (*FITBIT LIMITATION*) per query
	
	.EXAMPLE
		Get-HRdata -QueryDate "2016-03-13"			
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[ValidateLength(1, 140)]
		[String]$QueryDate = $(Get-Date ([System.DateTime]::Now).AddDays(-1) -Format "yyyy-MM-dd")
	)
	BEGIN
	{
		(Write-Status -Message "START  - Get-HRdata function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
	PROCESS
	{
		try
		{
			if (!$(Test-Date -inputDate $QueryDate))
			{
				[String]$QueryDate = $(Get-Date ([System.DateTime]::Now).AddDays(-1) -Format "yyyy-MM-dd")
			}
			else
			{
				[String]$QueryDate = $(Get-Date $QueryDate -Format "yyyy-MM-dd")
			}
			
			$Script:psFitb1tHRQueryDate = $QueryDate
			
			# Call our main connect routine to setup the oAuth
			$psFitb1tAuthCode = Connect-OAuthFitbit
			
			(Write-Status -Message "START  - Sending HTTP POST via REST to Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			
			$Script:psFitb1tGetHRurl = "https://api.fitbit.com/1/user/-/activities/heart/date/$($psFitb1tHRQueryDate)/1d/1sec/time/00:00/23:59.json"
			
			Write-Verbose "Sending to URL $($psFitb1tGetHRurl)"
			Write-Verbose "This request:  Headers=$psFitb1tAuthCode"
			
			# Call the REST API to handle the final OAUTH POST
			$retData = Invoke-RestMethod -Method Get -Uri $psFitb1tGetHRurl -Headers @{ 'Authorization' = "Bearer " + $psFitb1tAuthCode } -ContentType "application/x-www-form-urlencoded"
			
			#Write the output
			$output = @()
			$output = New-Object -TypeName PSObject			
			
			#Assign the dataset to custom obj
			$output = $retData.'activities-heart-intraday'.dataset
			
			#Add the query date to output object
			$output | Add-Member -Name 'Date' -Value $($psFitb1tHRQueryDate) -MemberType NoteProperty -Force
			
			#Write to csv
			$output | Export-Csv -NoTypeInformation "$($Script:psFitb1tInvocationPath)FitbitHR_$($psFitb1tHRQueryDate).csv"
			
			#Write to xls
			Export-FitbitXLS -objInput $output "$($Script:psFitb1tInvocationPath)FitbitHR_$($psFitb1tHRQueryDate).xlsx" -appendSheet:$false -worksheetName "$psFitb1tHRQueryDate" -chartType "xlLine"
			
			
			(Write-Status -Message "FINISH - Sending HTTP POST via REST to Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
		}
		catch
		{
			Throw $("ERROR OCCURRED RETRIEVING HR DATA " + $_.Exception.Message)
		}
	}
	END
	{
		#write last query date to registry
		New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tHRQueryDate" -value "$Script:psFitb1tHRQueryDate" -Force | out-null		
		(Write-Status -Message "FINISH - Get-HRdata function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
}

function Get-HRMin
{
	<#
	.SYNOPSIS
		Get's your minimum heart rate
	
	.DESCRIPTION
		Author:  		Bert Jansen
		Description:	Sends a request for 24hrs of HR data using OAuth and REST and outputs the lowest heart rate
	
	.PARAMETER QueryDate
		The single 24hr Date to retrieve HR data (*FITBIT LIMITATION*) per query
	
	.EXAMPLE
		Get-HRMin -QueryDate "2016-03-13"			
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[ValidateLength(1, 140)]
		[String]$QueryDate = $(Get-Date ([System.DateTime]::Now) -Format "yyyy-MM-dd")
	)
	BEGIN
	{
		(Write-Status -Message "START  - Get-HRMin function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
	PROCESS
	{
		try
		{
			if (!$(Test-Date -inputDate $QueryDate))
			{
				[String]$QueryDate = $(Get-Date ([System.DateTime]::Now) -Format "yyyy-MM-dd")
			}
			else
			{
				[String]$QueryDate = $(Get-Date $QueryDate -Format "yyyy-MM-dd")
			}
			
			$Script:psFitb1tHRQueryDate = $QueryDate
			
			# Call our main connect routine to setup the oAuth
			$psFitb1tAuthCode = Connect-OAuthFitbit
			
			(Write-Status -Message "START  - Sending HTTP POST via REST to Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			
			$Script:psFitb1tGetHRurl = "https://api.fitbit.com/1/user/-/activities/heart/date/$($psFitb1tHRQueryDate)/1d/1sec/time/00:00/23:59.json"
			
			Write-Verbose "Sending to URL $($psFitb1tGetHRurl)"
			Write-Verbose "This request:  Headers=$psFitb1tAuthCode"
			
			# Call the REST API to handle the final OAUTH POST
			$retData = Invoke-RestMethod -Method Get -Uri $psFitb1tGetHRurl -Headers @{ 'Authorization' = "Bearer " + $psFitb1tAuthCode } -ContentType "application/x-www-form-urlencoded"
			
			#Write the output
			$output = @()
			$output = New-Object -TypeName PSObject			
			
			#Assign the dataset to custom obj
			$output = $retData.'activities-heart-intraday'.dataset
			
            $lowest = 999;

            foreach($hr in $output)
            {
                if ($hr.value -lt $lowest)
                {
                    $lowest = $hr.value;
                }
            }

            (Write-Status -Message "YOUR MINIMAL HEARTRATE AT $QueryDate WAS: $lowest" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			
			
			(Write-Status -Message "FINISH - Sending HTTP POST via REST to Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)

            return $lowest;
		}
		catch
		{
			Throw $("ERROR OCCURRED RETRIEVING HR DATA " + $_.Exception.Message)
		}
	}
	END
	{
		#write last query date to registry
		New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tHRQueryDate" -value "$Script:psFitb1tHRQueryDate" -Force | out-null		
		(Write-Status -Message "FINISH - Get-HRdata function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
}


function Get-HRMax
{
	<#
	.SYNOPSIS
		Get's your maximum heart rate
	
	.DESCRIPTION
		Author:  		Bert Jansen
		Description:	Sends a request for 24hrs of HR data using OAuth and REST and outputs the highest heart rate
	
	.PARAMETER QueryDate
		The single 24hr Date to retrieve HR data (*FITBIT LIMITATION*) per query
	
	.EXAMPLE
		Get-HRMax -QueryDate "2016-03-13"			
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[ValidateLength(1, 140)]
		[String]$QueryDate = $(Get-Date ([System.DateTime]::Now).AddDays(-1) -Format "yyyy-MM-dd")
	)
	BEGIN
	{
		(Write-Status -Message "START  - Get-HRMax function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
	PROCESS
	{
		try
		{
			if (!$(Test-Date -inputDate $QueryDate))
			{
				[String]$QueryDate = $(Get-Date ([System.DateTime]::Now).AddDays(-1) -Format "yyyy-MM-dd")
			}
			else
			{
				[String]$QueryDate = $(Get-Date $QueryDate -Format "yyyy-MM-dd")
			}
			
			$Script:psFitb1tHRQueryDate = $QueryDate
			
			# Call our main connect routine to setup the oAuth
			$psFitb1tAuthCode = Connect-OAuthFitbit
			
			(Write-Status -Message "START  - Sending HTTP POST via REST to Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			
			$Script:psFitb1tGetHRurl = "https://api.fitbit.com/1/user/-/activities/heart/date/$($psFitb1tHRQueryDate)/1d/1sec/time/00:00/23:59.json"
			
			Write-Verbose "Sending to URL $($psFitb1tGetHRurl)"
			Write-Verbose "This request:  Headers=$psFitb1tAuthCode"
			
			# Call the REST API to handle the final OAUTH POST
			$retData = Invoke-RestMethod -Method Get -Uri $psFitb1tGetHRurl -Headers @{ 'Authorization' = "Bearer " + $psFitb1tAuthCode } -ContentType "application/x-www-form-urlencoded"
			
			#Write the output
			$output = @()
			$output = New-Object -TypeName PSObject			
			
			#Assign the dataset to custom obj
			$output = $retData.'activities-heart-intraday'.dataset
			
            $max = 0;

            foreach($hr in $output)
            {
                if ($hr.value -gt $max)
                {
                    $max = $hr.value;
                }
            }

            (Write-Status -Message "YOUR MAXIMUM HEARTRATE AT $QueryDate WAS: $max" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			
			
			(Write-Status -Message "FINISH - Sending HTTP POST via REST to Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)

            return $max;
		}
		catch
		{
			Throw $("ERROR OCCURRED RETRIEVING HR DATA " + $_.Exception.Message)
		}
	}
	END
	{
		#write last query date to registry
		New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tHRQueryDate" -value "$Script:psFitb1tHRQueryDate" -Force | out-null		
		(Write-Status -Message "FINISH - Get-HRdata function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
}

function Get-HRAvg
{
	<#
	.SYNOPSIS
		Get's your average heart rate
	
	.DESCRIPTION
		Author:  		Bert Jansen
		Description:	Sends a request for 24hrs of HR data using OAuth and REST and outputs the average heart rate of the day
	
	.PARAMETER QueryDate
		The single 24hr Date to retrieve HR data (*FITBIT LIMITATION*) per query
	
	.EXAMPLE
		Get-HRAvg -QueryDate "2016-03-13"			
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[ValidateLength(1, 140)]
		[String]$QueryDate = $(Get-Date ([System.DateTime]::Now).AddDays(-1) -Format "yyyy-MM-dd")
	)
	BEGIN
	{
		(Write-Status -Message "START  - Get-HRAvg function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
	PROCESS
	{
		try
		{
			if (!$(Test-Date -inputDate $QueryDate))
			{
				[String]$QueryDate = $(Get-Date ([System.DateTime]::Now).AddDays(-1) -Format "yyyy-MM-dd")
			}
			else
			{
				[String]$QueryDate = $(Get-Date $QueryDate -Format "yyyy-MM-dd")
			}
			
			$Script:psFitb1tHRQueryDate = $QueryDate
			
			# Call our main connect routine to setup the oAuth
			$psFitb1tAuthCode = Connect-OAuthFitbit
			
			(Write-Status -Message "START  - Sending HTTP POST via REST to Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			
			$Script:psFitb1tGetHRurl = "https://api.fitbit.com/1/user/-/activities/heart/date/$($psFitb1tHRQueryDate)/1d/1sec/time/00:00/23:59.json"
			
			Write-Verbose "Sending to URL $($psFitb1tGetHRurl)"
			Write-Verbose "This request:  Headers=$psFitb1tAuthCode"
			
			# Call the REST API to handle the final OAUTH POST
			$retData = Invoke-RestMethod -Method Get -Uri $psFitb1tGetHRurl -Headers @{ 'Authorization' = "Bearer " + $psFitb1tAuthCode } -ContentType "application/x-www-form-urlencoded"
			
			#Write the output
			$output = @()
			$output = New-Object -TypeName PSObject			
			
			#Assign the dataset to custom obj
			$output = $retData.'activities-heart-intraday'.dataset
			
            $count = 0;
            $sum = 0;

            foreach($hr in $output)
            {
                if ($hr.value -gt 0)
                {
                    $count = $count + 1;
                    $sum = $sum + $hr.value;
                }
            }

            $average = [math]::round($sum / $count, 1);

            (Write-Status -Message "YOUR AVERAGE HEARTRATE AT $QueryDate WAS: $average" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			
			
			(Write-Status -Message "FINISH - Sending HTTP POST via REST to Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)

            return $average;
		}
		catch
		{
			Throw $("ERROR OCCURRED RETRIEVING HR DATA " + $_.Exception.Message)
		}
	}
	END
	{
		#write last query date to registry
		New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tHRQueryDate" -value "$Script:psFitb1tHRQueryDate" -Force | out-null		
		(Write-Status -Message "FINISH - Get-HRdata function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
}



function Get-HRmonth
{
<#
	.SYNOPSIS
		Get entire month of heartrate reports via psFitb1t's Get-HRdata
	
	.DESCRIPTION
		Determines how many possible days in the requested month and calls psFitb1t's Get-HRdata to retrieve the daily reports.  It first verifies if 
		you have already retrieved any reports for days in the queried month and if so, only processes missing days.
		
		Returns bool for overall success or failure.
	
	.PARAMETER QueryMonth
		A description of the QueryMonth parameter.
	
	.EXAMPLE
				PS C:\> Get-HRmonth -QueryMonth '2016-01'
				This queries all days for January, 2016 that do not already have reports on disk
	
	.NOTES
		Requires the primary Get-HRdata retrieval function.
#>	
	[CmdletBinding()]
	[OutputType([bool])]
	param
	(
		[Parameter(Mandatory = $true)]
		[System.String]
		$QueryMonth = "2016-01" #This will accept mult formats such as "01/2016","2016-01"
	)
	BEGIN
	{
		(Write-Status -Message "START  - Get-HRmonth function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
		
		Import-Module -Name psFitb1t -ea 'Stop' | Out-Null
		$nbrDaysInMonth = [DateTime]::DaysInMonth($([DateTime](Get-Date($QueryMonth))).Year, $([Datetime](Get-Date($QueryMonth))).Month)
		$daysToProcess = 0
		$cntProc = 0
	}
	PROCESS
	{
		try
		{
			(Write-Status -Message "START  - Requesting monthly HR data from Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			
			#Get total real days to process = days in month minus any existing days already processed
			for ($i = 1; $i -le $nbrDaysInMonth; $i++)
			{
				$day = ("{0:D2}" -f $i)
				if (!(Test-Path -Path "$((Get-Module psFitb1t).ModuleBase)\FitbitHR_$(([Datetime](Get-Date($QueryMonth))).ToString('yyyy'))-$(([Datetime](Get-Date($QueryMonth))).ToString('MM'))-$($day).xlsx"))
				{
					$daysToProcess++
				}
			}
			
			(Write-Status -Message "START  - Requesting $($daysToProcess) days of HR data from Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
			#Process the missing days and provide accurate progress counter based on number computed above
			for ($i = 1; $i -le $nbrDaysInMonth; $i++)
			{
				$day = ("{0:D2}" -f $i)
				if (!(Test-Path -Path "$((Get-Module psFitb1t).ModuleBase)\FitbitHR_$(([Datetime](Get-Date($QueryMonth))).ToString('yyyy'))-$(([Datetime](Get-Date($QueryMonth))).ToString('MM'))-$($day).xlsx"))
				{
					$cntProc++
					Write-Verbose "$((Get-Module psFitb1t).ModuleBase)\FitbitHR_$(([Datetime](Get-Date($QueryMonth))).ToString('yyyy'))-$(([Datetime](Get-Date($QueryMonth))).ToString('MM'))-$($day).xlsx missing!"
					Write-Verbose "Running: Get-HRData -QueryDate ""$($([Datetime](Get-Date($QueryMonth))).ToString('yyyy'))-$($([Datetime](Get-Date($QueryMonth))).ToString('MM'))-$($day)"" `n"
					Write-Progress -Activity "Retrieving heartrate data for $($([Datetime](Get-Date($QueryMonth))).Year)-$($([Datetime](Get-Date($QueryMonth))).Month)-$($day)" -PercentComplete (($cntProc / $daysToProcess) * 100)
					(Write-Status -Message "START  - Requesting HR data for $($([Datetime](Get-Date($QueryMonth))).Year)-$($([Datetime](Get-Date($QueryMonth))).Month)-$($day) from Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
					Get-HRData -QueryDate "$($([Datetime](Get-Date($QueryMonth))).Year)-$($([Datetime](Get-Date($QueryMonth))).Month)-$($day)"					
				}
			}
			(Write-Status -Message "FINISH  - Requesting monthly HR data from Fitbit" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
		}
		catch
		{
			Throw $("ERROR OCCURRED RETRIEVING MONTHLY HR DATA " + $_.Exception.Message)
		}
	}
	END
	{
		(Write-Status -Message "FINISH  - Get-HRmonth function execution" -Status "INFO" -Debugging:$psFitb1tDebugging -Logging:$psFitb1tLogging -Logpath $psFitb1tLogPath)
	}
}


Function Export-FitbitXLS
{
  <#
.SYNOPSIS
  Saves data to Excel using com object
.DESCRIPTION
  The Export-FitbitXLS function allows you to save data to an Excel file
.PARAMETER objInput
  Specifies the input object
.PARAMETER outputPath
  Specifies the path to the output XLS file
.PARAMETER worksheetName
  The name for the worksheet
.PARAMETER sheetIndex
  Specify if END
.PARAMETER chartType
  Type of chart based on [microsoft.Office.Interop.Excel.XlChartType]
.PARAMETER appendSheet
  Append or overwrite
.EXAMPLE
  Export-FitbitXLS -objInput $obj "$($Script:psFitb1tInvocationPath)FitbitHR_$($psFitb1tHRQueryDate).xlsx" -appendSheet:$false -worksheetName "$psFitb1tHRQueryDate" -chartType "xlLine"
#>
	param (
		[parameter(ValueFromPipeline = $true, Position = 1)]
		[ValidateNotNullOrEmpty()]
		$objInput,
		[parameter(Position = 2)]
		[ValidateNotNullOrEmpty()]
		[string]$outputPath,
		[string]$worksheetName = ("Sheet $((Get-Date).Ticks)"),
		[switch]$newSheetLast = $true,
		[PSObject]$chartType,
		[switch]$appendSheet = $true
	)	
	BEGIN
	{
		#Nested internal helper clipboard function specific to this XLS function
		#Adds txt strings to txtbox then to clipboard
		function Add-ClipBoardTxt
		{
			param (
				[String]$txtInput
			)
			process
			{
				try
				{					
					Add-Type -AssemblyName System.Windows.Forms | Out-Null
					$tmpTextbox = New-Object System.Windows.Forms.TextBox
					$tmpTextbox.Multiline = $true
					$tmpTextbox.Text = $txtInput
					$tmpTextbox.SelectAll()
					$tmpTextbox.Copy()
				}
				catch
				{
					Throw $("ERROR OCCURRED COPYING EXCEL DATA TO CLIPBOARD " + $_.Exception.Message)
				}
			}
		}
		#Nested internal helper clipboard function specific to this XLS function
		#Builds internal array with header row and sends all to clipboard at once
		#To send each of thousands cells one at time to Excel takes far too long this is much faster
		function Send-ToClipboard
		{
			param (
				[PSObject[]]$objConvert,
				[Switch]$headerRow
			)
			process
			{
				try
				{
					$tmpArray = @()
					if ($headerRow)
					{
						$line = ""
						$objConvert | Get-Member -MemberType Property, NoteProperty, CodeProperty | Select -Property Name | %{ $line += ($_.Name.tostring() + "`t") }
						$tmpArray += ($line.TrimEnd("`t") + "`r")
					}
					else
					{
						foreach ($obj in $objConvert)
						{
							$line = ""
							$obj | Get-Member -MemberType Property, NoteProperty | %{
								$Name = $_.Name
								if (!$obj.$Name) { $obj.$Name = "" }
								$line += ([string]$obj.$Name + "`t")
							}
							$tmpArray += ($line.TrimEnd("`t") + "`r")
						}
					}
					Add-ClipBoardTxt $tmpArray
				}
				catch
				{
					Throw $("ERROR OCCURRED ADDING EXCEL DATA TO CLIPBOARD " + $_.Exception.Message)
				}
			}
		}		
		try
		{			
			[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Office.Interop.Excel") | Out-Null
			if ($chartType)
			{
				[Microsoft.Office.Interop.Excel.XlChartType]$chartType = $chartType
			}
			$excelObj = New-Object -ComObject "Excel.Application"
			$originalAlerts = $excelObj.DisplayAlerts
			$excelObj.DisplayAlerts = $false
			if (Test-Path -Path $outputPath -PathType "Leaf")
			{
				$excelWorkbook = $excelObj.Workbooks.Open($outputPath)
			}
			else
			{
				$excelWorkbook = $excelObj.Workbooks.Add()
			}
			$excelSheet = $excelObj.Worksheets.Add($excelWorkbook.Worksheets.Item(1))
			if (!$appendSheet)
			{
				$excelWorkbook.Sheets | where { $_ -ne $excelSheet } | %{ $_.Delete() }
			}
			$excelSheet.Name = $worksheetName
			if ($newSheetLast -eq $true -and $excelWorkbook.Sheets.Count -ge 2)
			{
				$sheetCount = $excelWorkbook.Sheets.Count
				2..($sheetCount) | %{
					$excelWorkbook.Sheets.Item($_).Move($excelWorkbook.Sheets.Item($_ - 1))
				}
			}
			$excelSheet.Activate()
			$tmpArray = @()			
		}
		catch
		{
			Throw $("ERROR OCCURRED RELEASING COM OBJECTS " + $_.Exception.Message)
		}		
	}	
	PROCESS
	{
		try
		{
			$tmpArray += $objInput
		}
		catch
		{
			Throw $("ERROR OCCURRED CREATING EXCEL ARRAY " + $_.Exception.Message)
		}
	}	
	END
	{
		try
		{
			Send-ToClipboard $tmpArray -headerRow:$True
			$selection = $excelSheet.Range("A1")
			$selection.Select() | Out-Null
			$excelSheet.Paste()
			$excelSheet.UsedRange.HorizontalAlignment = [microsoft.Office.Interop.Excel.XlHAlign]::xlHAlignCenter
			
			Send-ToClipboard $tmpArray
			$selection = $excelSheet.Range("A2")
			$selection.Select() | Out-Null
			$excelSheet.Paste() | Out-Null
			$selection = $excelSheet.Range("A1")
			$selection.Select() | Out-Null
			
			$excelSheet.UsedRange.EntireColumn.AutoFit() | Out-Null
			$excelWorkbook.Sheets.Item(1).Select()
			if ($chartType)
			{
				$chart = $excelSheet.Shapes.AddChart().Chart
				$chart.ChartType = $chartType
				$chart.ChartTitle.Text = "Fitbit Heartrates for: $($Script:psFitb1tHRQueryDate)"
				$excelSheet.Shapes.Item("Chart 1").top = 120
				$excelSheet.Shapes.Item("Chart 1").width = 1200
				$excelSheet.Shapes.Item("Chart 1").Height = 400
				$excelSheet.Shapes.Item("Chart 1").Left = 180
			}
			$range = $excelSheet.Range("o2", "s3")
			$range.Merge() | Out-Null
			$range.VerticalAlignment = -4160
			$range.Style = 'Title'
			
			$selection = $excelSheet.Range("P5", "R5")
			$selection.Select() | Out-Null
			$excelSheet.UsedRange.HorizontalAlignment = [microsoft.Office.Interop.Excel.XlHAlign]::xlHAlignCenter
			$excelSheet.UsedRange.EntireColumn.AutoFit() | Out-Null
			
			$excelSheet.columns.item('p').NumberFormat = "[Blue]#0"
			$excelSheet.columns.item('q').NumberFormat = "[Blue]#0"
			$excelSheet.columns.item('r').NumberFormat = "[Blue]#0"
			
			$excelObj.Cells.Item(2, 15).Value() = "Fitbit Heartrates for: $($Script:psFitb1tHRQueryDate)"
			
			$excelObj.Cells.Item(1, 2).Value() = "Time"
			$excelObj.Cells.Item(1, 3).Value() = "HeartRate"
			
			$excelObj.Cells.Item(5, 16).Value() = "Minimum"
			$excelObj.Cells.Item(5, 17).Value() = "Maximum"
			$excelObj.Cells.Item(5, 18).Value() = "Average"
			$strFormula1 = "=MIN(C2:C99999)"
			$strFormula2 = "=MAX(C2:C99999)"
			$strFormula3 = "=AVERAGE(C2:C99999)"
			
			$excelObj.Cells.Item(6, 16).Formula = $strFormula1
			$excelObj.Cells.Item(6, 17).Formula = $strFormula2
			$excelObj.Cells.Item(6, 18).Formula = $strFormula3
			$excelObj.Cells.Item(5, 16).Font.Bold = $True
			$excelObj.Cells.Item(5, 17).Font.Bold = $True
			$excelObj.Cells.Item(5, 18).Font.Bold = $True
			
			#Auto fit everything so it looks better
			$usedRange = $excelSheet.UsedRange
			$usedRange.EntireColumn.AutoFit() | Out-Null
			$excelWorkbook.Sheets.Item(1).Select()
			
			$excelWorkbook.SaveAs($outputPath)
			$excelWorkbook.Saved = $True
			$excelWorkbook.Close()
			$excelObj.DisplayAlerts = $originalAlerts
			$excelObj.Quit()
			
			#Cleanup all this com object crap what a PITA Excel com objects are!!
			Release-Ref $chart
			Release-Ref $selection
			Release-Ref $range
			Release-Ref $usedRange
			Release-Ref $excelSheet
			Release-Ref $excelWorkbook
			Release-Ref $excelObj			
			Remove-Variable chart | Out-Null
			Remove-Variable selection | Out-Null
			Remove-Variable range | Out-Null
			Remove-Variable usedRange | Out-Null
			Remove-Variable excelSheet | Out-Null
			Remove-Variable excelWorkbook | Out-Null
			Remove-Variable excelObj | Out-Null
			Start-Sleep 5
			[void][System.GC]::Collect()
			[void][System.GC]::WaitForPendingFinalizers()
		}
		catch
		{
			Throw $("ERROR OCCURRED CREATING EXCEL CHART AND SAVING FILE " + $_.Exception.Message)
		}
	}
}

function Release-Ref
{
<#
.SYNOPSIS
  Kills in use com objects (Excel is a PITA)
.DESCRIPTION
  Kills off com objects properly
.PARAMETER inputObj
  Specifies the objects to be released
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)]
		[ValidateNotNullOrEmpty()]
		[System.__ComObject]$inputObj
	)
	BEGIN
	{
	}
	PROCESS
	{
		try
		{
			[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$inputObj)
		}
		catch
		{
			Throw $("ERROR OCCURRED RELEASING COM OBJECTS " + $_.Exception.Message)
		}
	}
	END
	{
	}
}


#########################################################################

#endregion

#region Call-psFitb1t-API_psf

function Call-psFitb1t-API_psf
{
	#----------------------------------------------
	#region Import the Assemblies
	#----------------------------------------------
	[void][reflection.assembly]::Load('mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System.Windows.Forms, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System.Data, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System.Drawing, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
	[void][reflection.assembly]::Load('System.Xml, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System.DirectoryServices, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
	[void][reflection.assembly]::Load('System.Core, Version=3.5.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089')
	[void][reflection.assembly]::Load('System.ServiceProcess, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')
	#endregion Import Assemblies
	
	#----------------------------------------------
	#region  Form Objects
	#----------------------------------------------
	[System.Windows.Forms.Application]::EnableVisualStyles()
	$frmFitbitAPIInformation = New-Object 'System.Windows.Forms.Form'
	$buttonCancel = New-Object 'System.Windows.Forms.Button'
	$buttonBack = New-Object 'System.Windows.Forms.Button'
	$buttonFinish = New-Object 'System.Windows.Forms.Button'
	$tabcontrolWizard = New-Object 'System.Windows.Forms.TabControl'
	$tabpageStep1 = New-Object 'System.Windows.Forms.TabPage'
	$txtpsFitb1tClientID = New-Object 'System.Windows.Forms.TextBox'
	$labelpsFitb1tClientID = New-Object 'System.Windows.Forms.Label'
	$tabpageStep2 = New-Object 'System.Windows.Forms.TabPage'
	$txtpsFitb1tRedirectURL = New-Object 'System.Windows.Forms.TextBox'
	$labelpsFitb1tRedirectURL = New-Object 'System.Windows.Forms.Label'
	$tabpageStep3 = New-Object 'System.Windows.Forms.TabPage'
	$txtpsFitb1tHRQueryDate = New-Object 'System.Windows.Forms.TextBox'
	$labelpsFitb1tHRQueryDate = New-Object 'System.Windows.Forms.Label'
	$tabpageStep4 = New-Object 'System.Windows.Forms.TabPage'
	$txtpsFitb1tTokenAge = New-Object 'System.Windows.Forms.TextBox'
	$labelpsFitb1tTokenAge = New-Object 'System.Windows.Forms.Label'
	$buttonNext = New-Object 'System.Windows.Forms.Button'
	$InitialFormWindowState = New-Object 'System.Windows.Forms.FormWindowState'
	#endregion  Form Objects
	
	
	function Validate-WizardPage
	{
		[OutputType([boolean])]
		param ([System.Windows.Forms.TabPage]$tabPage)
		
		if ($tabPage -eq $tabpageStep1)
		{
			if (-not $txtpsFitb1tClientID.Text)
			{
				return $false
			}
			
			return $true
		}
		elseif ($tabPage -eq $tabpageStep2)
		{
			if (-not $txtpsFitb1tRedirectURL.Text)
			{
				return $false
			}
			
			return $true
		}
		elseif ($tabPage -eq $tabpageStep3)
		{
			if (-not $txtpsFitb1tHRQueryDate.Text)
			{
				return $false
			}
			
			return $true
		}
		elseif ($tabPage -eq $tabpageStep4)
		{
			if (-not $txtpsFitb1tTokenAge.Text)
			{
				return $false
			}
			
			return $true
		}
		return $false
	}
	
	$buttonFinish_Click = {
		if ($txtpsFitb1tClientID.Text) { New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tClientID" -value "$($txtpsFitb1tClientID.Text)" | out-null }
		if ($txtpsFitb1tRedirectURL.Text) { New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tRedirectURL" -value "$($txtpsFitb1tRedirectURL.Text)" | out-null }
		if ($txtpsFitb1tHRQueryDate.Text) { New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tHRQueryDate" -value "$($txtpsFitb1tHRQueryDate.Text)" | out-null }
		if ($txtpsFitb1tTokenAge.Text) { New-ItemProperty HKCU:\Software\psFitb1t -name "psFitb1tTokenAge" -value "$($txtpsFitb1tTokenAge.Text)" | out-null }
	}
	
	#region Events and Functions
	$frmFitbitAPIInformation_Load = {
		Update-NavButtons
		
		# Reg key is there, but we must have a missing value(s)
		$psFitb1tClientID = (Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tClientID")
		$psFitb1tRedirectURL = (Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tRedirectURL")
		$psFitb1tHRQueryDate = (Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tHRQueryDate")
		$psFitb1tTokenAge = (Get-Item HKCU:\Software\psFitb1t).getvalue("psFitb1tTokenAge")
		
		# Check for any single missing values and prompt for those that are missing
		if ($psFitb1tClientID)
		{
			$tabcontrolWizard.TabPages.Remove($tabpageStep1)
		}
		if ($psFitb1tRedirectURL)
		{
			$tabcontrolWizard.TabPages.Remove($tabpageStep2)
		}
		#if ($psFitb1tHRQueryDate)
		#{
			$tabcontrolWizard.TabPages.Remove($tabpageStep3)
		#}
		#if ($psFitb1tTokenAge)
		#{
			$tabcontrolWizard.TabPages.Remove($tabpageStep4)
		#}
	}
	
	function Update-NavButtons
	{
		<# 
			.DESCRIPTION
			Validates the current tab and Updates the Next, Prev and Finish buttons.
		#>
		$enabled = Validate-WizardPage $tabcontrolWizard.SelectedTab
		$buttonNext.Enabled = $enabled -and ($tabcontrolWizard.SelectedIndex -lt $tabcontrolWizard.TabCount - 1)
		$buttonBack.Enabled = $tabcontrolWizard.SelectedIndex -gt 0
		$buttonFinish.Enabled = $enabled -and ($tabcontrolWizard.SelectedIndex -eq $tabcontrolWizard.TabCount - 1)
		#Uncomment to Hide Buttons
		#$buttonNext.Visible = ($tabcontrolWizard.SelectedIndex -lt $tabcontrolWizard.TabCount - 1)
		#$buttonFinish.Visible = ($tabcontrolWizard.SelectedIndex -eq $tabcontrolWizard.TabCount - 1)
	}
	
	$script:DeselectedIndex = -1
	$tabcontrolWizard_Deselecting = [System.Windows.Forms.TabControlCancelEventHandler]{
		#Event Argument: $_ = [System.Windows.Forms.TabControlCancelEventArgs]
		# Store the previous tab index
		$script:DeselectedIndex = $_.TabPageIndex
	}
	
	$tabcontrolWizard_Selecting = [System.Windows.Forms.TabControlCancelEventHandler]{
		#Event Argument: $_ = [System.Windows.Forms.TabControlCancelEventArgs]
		# We only validate if we are moving to the Next TabPage.
		# Users can move back without validating
		if ($script:DeselectedIndex -ne -1 -and $script:DeselectedIndex -lt $_.TabPageIndex)
		{
			#Validate each page until we reach the one we want
			for ($index = $script:DeselectedIndex; $index -lt $_.TabPageIndex; $index++)
			{
				$_.Cancel = -not (Validate-WizardPage $tabcontrolWizard.TabPages[$index])
				
				if ($_.Cancel)
				{
					# Cancel and Return if validation failed.
					return;
				}
			}
		}
		Update-NavButtons
	}
	
	$buttonBack_Click = {
		#Go to the previous tab page
		if ($tabcontrolWizard.SelectedIndex -gt 0)
		{
			$tabcontrolWizard.SelectedIndex--
		}
	}
	
	$buttonNext_Click = {
		#Go to the next tab page
		if ($tabcontrolWizard.SelectedIndex -lt $tabcontrolWizard.TabCount - 1)
		{
			$tabcontrolWizard.SelectedIndex++
		}
	}
	
	#endregion
	
	#------------------------------------------------------
	# Events: Call Update-NavButtons to trigger validation
	#------------------------------------------------------
	
	$txtpsFitb1tClientID_TextChanged = {
		Update-NavButtons
	}
	
	$txtpsFitb1tRedirectURL_TextChanged = {
		Update-NavButtons
	}
	
	$txtpsFitb1tHRQueryDate_TextChanged = {
		Update-NavButtons
	}
	
	$txtpsFitb1tTokenAge_TextChanged = {
		Update-NavButtons
	}
	
	
	$tabcontrolWizard_SelectedIndexChanged = {
		Update-NavButtons
	}
	
	$buttonCancel_Click = {
		$frmFitbitAPIInformation.Close()
	}
	
	#----------------------------------------------
	#region cleanup Events
	#----------------------------------------------
	
	$Form_StateCorrection_Load =
	{
		#Correct the initial state of the form to prevent the .Net maximized form issue
		$frmFitbitAPIInformation.WindowState = $InitialFormWindowState
	}
	
	$Form_StoreValues_Closing =
	{
		#Store the control values
		$script:psFitb1t_API_txtpsFitb1tClientID = $txtpsFitb1tClientID.Text
		$script:psFitb1t_API_txtpsFitb1tRedirectURL = $txtpsFitb1tRedirectURL.Text
		$script:psFitb1t_API_txtpsFitb1tHRQueryDate = $txtpsFitb1tHRQueryDate.Text
		$script:psFitb1t_API_txtpsFitb1tTokenAge = $txtpsFitb1tTokenAge.Text
	}
	
	
	$Form_Cleanup_FormClosed =
	{
		#Remove all event handlers from the controls
		try
		{
			$buttonCancel.remove_Click($buttonCancel_Click)
			$buttonBack.remove_Click($buttonBack_Click)
			$buttonFinish.remove_Click($buttonFinish_Click)
			$txtpsFitb1tClientID.remove_TextChanged($txtpsFitb1tClientID_TextChanged)
			$txtpsFitb1tRedirectURL.remove_TextChanged($txtpsFitb1tRedirectURL_TextChanged)
			$txtpsFitb1tHRQueryDate.remove_TextChanged($txtpsFitb1tHRQueryDate_TextChanged)
			$txtpsFitb1tTokenAge.remove_TextChanged($txtpsFitb1tTokenAge_TextChanged)
			$tabcontrolWizard.remove_SelectedIndexChanged($tabcontrolWizard_SelectedIndexChanged)
			$tabcontrolWizard.remove_Selecting($tabcontrolWizard_Selecting)
			$tabcontrolWizard.remove_Deselecting($tabcontrolWizard_Deselecting)
			$buttonNext.remove_Click($buttonNext_Click)
			$frmFitbitAPIInformation.remove_Load($frmFitbitAPIInformation_Load)
			$frmFitbitAPIInformation.remove_Load($Form_StateCorrection_Load)
			$frmFitbitAPIInformation.remove_Closing($Form_StoreValues_Closing)
			$frmFitbitAPIInformation.remove_FormClosed($Form_Cleanup_FormClosed)
		}
		catch [Exception]
		{ }
	}
	#endregion cleanup Events
	
	#----------------------------------------------
	#region Generated Form Code
	#----------------------------------------------
	$frmFitbitAPIInformation.SuspendLayout()
	$tabcontrolWizard.SuspendLayout()
	$tabpageStep1.SuspendLayout()
	$tabpageStep2.SuspendLayout()
	$tabpageStep3.SuspendLayout()
	$tabpageStep4.SuspendLayout()
	#
	# frmFitbitAPIInformation
	#
	$frmFitbitAPIInformation.Controls.Add($buttonCancel)
	$frmFitbitAPIInformation.Controls.Add($buttonBack)
	$frmFitbitAPIInformation.Controls.Add($buttonFinish)
	$frmFitbitAPIInformation.Controls.Add($tabcontrolWizard)
	$frmFitbitAPIInformation.Controls.Add($buttonNext)
	$frmFitbitAPIInformation.AcceptButton = $buttonFinish
	$frmFitbitAPIInformation.CancelButton = $buttonCancel
	$frmFitbitAPIInformation.ClientSize = '537, 180'
	$frmFitbitAPIInformation.FormBorderStyle = 'FixedDialog'
	$frmFitbitAPIInformation.MaximizeBox = $False
	$frmFitbitAPIInformation.Name = "frmFitbitAPIInformation"
	$frmFitbitAPIInformation.StartPosition = 'CenterScreen'
	$frmFitbitAPIInformation.Text = "Fitbit API Information"
	$frmFitbitAPIInformation.add_Load($frmFitbitAPIInformation_Load)
	#
	# buttonCancel
	#
	$buttonCancel.Anchor = 'Bottom, Right'
	$buttonCancel.DialogResult = 'Cancel'
	$buttonCancel.Location = '369, 145'
	$buttonCancel.Name = "buttonCancel"
	$buttonCancel.Size = '75, 23'
	$buttonCancel.TabIndex = 4
	$buttonCancel.Text = "&Cancel"
	$buttonCancel.UseVisualStyleBackColor = $True
	$buttonCancel.add_Click($buttonCancel_Click)
	#
	# buttonBack
	#
	$buttonBack.Anchor = 'Bottom, Left'
	$buttonBack.Location = '13, 145'
	$buttonBack.Name = "buttonBack"
	$buttonBack.Size = '75, 23'
	$buttonBack.TabIndex = 1
	$buttonBack.Text = "< &Back"
	$buttonBack.UseVisualStyleBackColor = $True
	$buttonBack.add_Click($buttonBack_Click)
	#
	# buttonFinish
	#
	$buttonFinish.Anchor = 'Bottom, Right'
	$buttonFinish.DialogResult = 'OK'
	$buttonFinish.Location = '450, 145'
	$buttonFinish.Name = "buttonFinish"
	$buttonFinish.Size = '75, 23'
	$buttonFinish.TabIndex = 3
	$buttonFinish.Text = "&Finish"
	$buttonFinish.UseVisualStyleBackColor = $True
	$buttonFinish.add_Click($buttonFinish_Click)
	#
	# tabcontrolWizard
	#
	$tabcontrolWizard.Controls.Add($tabpageStep1)
	$tabcontrolWizard.Controls.Add($tabpageStep2)
	$tabcontrolWizard.Controls.Add($tabpageStep3)
	$tabcontrolWizard.Controls.Add($tabpageStep4)
	$tabcontrolWizard.Anchor = 'Top, Bottom, Left, Right'
	$tabcontrolWizard.Location = '13, 12'
	$tabcontrolWizard.Name = "tabcontrolWizard"
	$tabcontrolWizard.SelectedIndex = 0
	$tabcontrolWizard.Size = '512, 127'
	$tabcontrolWizard.TabIndex = 0
	$tabcontrolWizard.add_SelectedIndexChanged($tabcontrolWizard_SelectedIndexChanged)
	$tabcontrolWizard.add_Selecting($tabcontrolWizard_Selecting)
	$tabcontrolWizard.add_Deselecting($tabcontrolWizard_Deselecting)
	#
	# tabpageStep1
	#
	$tabpageStep1.Controls.Add($txtpsFitb1tClientID)
	$tabpageStep1.Controls.Add($labelpsFitb1tClientID)
	$tabpageStep1.Location = '4, 22'
	$tabpageStep1.Name = "tabpageStep1"
	$tabpageStep1.Padding = '3, 3, 3, 3'
	$tabpageStep1.Size = '504, 101'
	$tabpageStep1.TabIndex = 0
	$tabpageStep1.Text = "Client ID"
	$tabpageStep1.UseVisualStyleBackColor = $True
	#
	# txtpsFitb1tClientID
	#
	$txtpsFitb1tClientID.Location = '168, 43'
	$txtpsFitb1tClientID.Name = "txtpsFitb1tClientID"
	$txtpsFitb1tClientID.Size = '259, 20'
	$txtpsFitb1tClientID.TabIndex = 1
	$txtpsFitb1tClientID.add_TextChanged($txtpsFitb1tClientID_TextChanged)
	#
	# labelpsFitb1tClientID
	#
	$labelpsFitb1tClientID.AutoSize = $True
	$labelpsFitb1tClientID.Location = '115, 46'
	$labelpsFitb1tClientID.Name = "labelpsFitb1tClientID"
	$labelpsFitb1tClientID.Size = '47, 13'
	$labelpsFitb1tClientID.TabIndex = 0
	$labelpsFitb1tClientID.Text = "Client ID"
	#
	# tabpageStep2
	#
	$tabpageStep2.Controls.Add($txtpsFitb1tRedirectURL)
	$tabpageStep2.Controls.Add($labelpsFitb1tRedirectURL)
	$tabpageStep2.Location = '4, 22'
	$tabpageStep2.Name = "tabpageStep2"
	$tabpageStep2.Padding = '3, 3, 3, 3'
	$tabpageStep2.Size = '504, 101'
	$tabpageStep2.TabIndex = 1
	$tabpageStep2.Text = "Redirect URL"
	$tabpageStep2.UseVisualStyleBackColor = $True
	#
	# txtpsFitb1tRedirectURL
	#
	$txtpsFitb1tRedirectURL.Location = '168, 42'
	$txtpsFitb1tRedirectURL.Name = "txtpsFitb1tRedirectURL"
	$txtpsFitb1tRedirectURL.Size = '259, 20'
	$txtpsFitb1tRedirectURL.TabIndex = 3
	$txtpsFitb1tRedirectURL.add_TextChanged($txtpsFitb1tRedirectURL_TextChanged)
	#
	# labelpsFitb1tRedirectURL
	#
	$labelpsFitb1tRedirectURL.AutoSize = $True
	$labelpsFitb1tRedirectURL.Location = '87, 45'
	$labelpsFitb1tRedirectURL.Name = "labelpsFitb1tRedirectURL"
	$labelpsFitb1tRedirectURL.Size = '72, 13'
	$labelpsFitb1tRedirectURL.TabIndex = 2
	$labelpsFitb1tRedirectURL.Text = "Redirect URL"
	#
	# tabpageStep3
	#
	$tabpageStep3.Controls.Add($txtpsFitb1tHRQueryDate)
	$tabpageStep3.Controls.Add($labelpsFitb1tHRQueryDate)
	$tabpageStep3.Location = '4, 22'
	$tabpageStep3.Name = "tabpageStep3"
	$tabpageStep3.Size = '504, 101'
	$tabpageStep3.TabIndex = 2
	$tabpageStep3.Text = "Last Query Date"
	$tabpageStep3.UseVisualStyleBackColor = $True
	#
	# txtpsFitb1tHRQueryDate
	#
	$txtpsFitb1tHRQueryDate.Location = '168, 43'
	$txtpsFitb1tHRQueryDate.Name = "txtpsFitb1tHRQueryDate"
	$txtpsFitb1tHRQueryDate.Size = '259, 20'
	$txtpsFitb1tHRQueryDate.TabIndex = 5
	$txtpsFitb1tHRQueryDate.add_TextChanged($txtpsFitb1tHRQueryDate_TextChanged)
	#
	# labelpsFitb1tHRQueryDate
	#
	$labelpsFitb1tHRQueryDate.AutoSize = $True
	$labelpsFitb1tHRQueryDate.Location = '78, 46'
	$labelpsFitb1tHRQueryDate.Name = "labelpsFitb1tHRQueryDate"
	$labelpsFitb1tHRQueryDate.Size = '84, 13'
	$labelpsFitb1tHRQueryDate.TabIndex = 4
	$labelpsFitb1tHRQueryDate.Text = "Last Query Date"
	#
	# tabpageStep4
	#
	$tabpageStep4.Controls.Add($txtpsFitb1tTokenAge)
	$tabpageStep4.Controls.Add($labelpsFitb1tTokenAge)
	$tabpageStep4.Location = '4, 22'
	$tabpageStep4.Name = "tabpageStep4"
	$tabpageStep4.Padding = '3, 3, 3, 3'
	$tabpageStep4.Size = '504, 101'
	$tabpageStep4.TabIndex = 3
	$tabpageStep4.Text = "Token Expiration"
	$tabpageStep4.UseVisualStyleBackColor = $True
	#
	# txtpsFitb1tTokenAge
	#
	$txtpsFitb1tTokenAge.Location = '168, 44'
	$txtpsFitb1tTokenAge.Name = "txtpsFitb1tTokenAge"
	$txtpsFitb1tTokenAge.Size = '259, 20'
	$txtpsFitb1tTokenAge.TabIndex = 7
	$txtpsFitb1tTokenAge.add_TextChanged($txtpsFitb1tTokenAge_TextChanged)
	#
	# labelpsFitb1tTokenAge
	#
	$labelpsFitb1tTokenAge.AutoSize = $True
	$labelpsFitb1tTokenAge.Location = '26, 47'
	$labelpsFitb1tTokenAge.Name = "labelpsFitb1tTokenAge"
	$labelpsFitb1tTokenAge.Size = '136, 13'
	$labelpsFitb1tTokenAge.TabIndex = 6
	$labelpsFitb1tTokenAge.Text = "Token Expiration DateTime"
	#
	# buttonNext
	#
	$buttonNext.Anchor = 'Bottom, Right'
	$buttonNext.Location = '288, 145'
	$buttonNext.Name = "buttonNext"
	$buttonNext.Size = '75, 23'
	$buttonNext.TabIndex = 2
	$buttonNext.Text = "&Next >"
	$buttonNext.UseVisualStyleBackColor = $True
	$buttonNext.add_Click($buttonNext_Click)
	$tabpageStep4.ResumeLayout()
	$tabpageStep3.ResumeLayout()
	$tabpageStep2.ResumeLayout()
	$tabpageStep1.ResumeLayout()
	$tabcontrolWizard.ResumeLayout()
	$frmFitbitAPIInformation.ResumeLayout()
	#endregion Generated Form Code
	
	#----------------------------------------------
	
	#Save the initial state of the form
	$InitialFormWindowState = $frmFitbitAPIInformation.WindowState
	#Init the OnLoad event to correct the initial state of the form
	$frmFitbitAPIInformation.add_Load($Form_StateCorrection_Load)
	#Clean up the control events
	$frmFitbitAPIInformation.add_FormClosed($Form_Cleanup_FormClosed)
	#Store the control values when form is closing
	$frmFitbitAPIInformation.add_Closing($Form_StoreValues_Closing)
	#Show the Form
	return $frmFitbitAPIInformation.ShowDialog()
	
}
#endregion

Export-ModuleMember Get-HRdata
Export-ModuleMember Get-HRmonth
Export-ModuleMember Get-HRMin
Export-ModuleMember Get-HRMax
Export-ModuleMember Get-HRAvg
Export-ModuleMember Set-FitbitOAuthTokens
	