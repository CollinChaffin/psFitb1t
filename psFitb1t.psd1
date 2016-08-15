#=======================================================================#
#
# Author:				Collin Chaffin
# Last Modified:		03-13-2016 12:00PM
# Filename:				psFitb1t.psd1
#
#
# Changelog:
#
#	v 1.0.0.1	:	03-13-2016	:	Initial release
#	v 1.0.0.2	:	03-30-2016	:	Added Get-HRmonth function
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

@{

# Script module or binary module file associated with this manifest
ModuleToProcess = 'psFitb1t.psm1'

# Version number of this module.
ModuleVersion = '1.0.0.3'

# ID used to uniquely identify this module
GUID = 'a6026be8-8b9f-452c-8b41-114ea9c9b372'
	
# Author of this module
Author = 'Collin Chaffin'

# Company or vendor of this module
CompanyName = ''

# Copyright statement for this module
Copyright = '(c) 2016. All rights reserved.'

# Description of the functionality provided by this module
Description = 'psFitb1t Windows Powershell Module - Provides Heartrate data via OAuth-based access to Fitbit API'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Name of the Windows PowerShell host required by this module
PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
PowerShellHostVersion = ''

# Minimum version of the .NET Framework required by this module
DotNetFrameworkVersion = '2.0'

# Minimum version of the common language runtime (CLR) required by this module
CLRVersion = '2.0.50727'

# Processor architecture (None, X86, Amd64, IA64) required by this module
ProcessorArchitecture = 'None'

# Modules that must be imported into the global environment prior to importing
# this module
RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to
# importing this module
ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
FormatsToProcess = @()

# Modules to import as nested modules of the module specified in
# ModuleToProcess
NestedModules = @()

# Functions to export from this module
FunctionsToExport = '*'

# Cmdlets to export from this module
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module
AliasesToExport = '*'

# List of all modules packaged with this module
ModuleList = @()

# List of all files packaged with this module
FileList = @()

# Private data to pass to the module specified in ModuleToProcess
PrivateData = ''
}







