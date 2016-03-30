*psFitb1t*: The original Powershell module to retrieve YOUR heartrate data
===================================================================
###### by Collin Chaffin  
[![Twitter Follow](https://img.shields.io/twitter/follow/collinchaffin.svg?style=social)](https://twitter.com/collinchaffin)

[![Development Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)](https://raw.githubusercontent.com/CollinChaffin/psFitb1t/master/README.md)[![GitHub license](https://img.shields.io/badge/license-Apache%202-blue.svg)](https://raw.githubusercontent.com/CollinChaffin/psFitb1t/master/LICENSE)[![GitHub stars](https://img.shields.io/github/stars/CollinChaffin/psFitb1t.svg)](https://github.com/CollinChaffin/psFitb1t/stargazers)[![GitHub forks](https://img.shields.io/github/forks/CollinChaffin/psFitb1t.svg)](https://github.com/CollinChaffin/psFitb1t/network)[![GitHub issues](https://img.shields.io/github/issues/CollinChaffin/psFitb1t.svg)](https://github.com/CollinChaffin/psFitb1t/issues)


Description:
------------

This module is designed to interact with FITBITR data using Fitbit's user-specific API information to perform OAuth connection to Fitbit and submit the request for your heart rate data for any 24 hour period.  

Due to Fitbit's trademark naming limitations to ensure it is clear that this module is **not developed by Fitbit**, I chose psFitb1t as my first logical choice of "psFitbit" may not have been allowed under their trademark restrictions for developers.

I originally wrote a similar framework for Twitter (PSTwitter) and saw a need and decided to fill it.  I frankly needed to track my daily heartrate and despite owning a Fitbit HR, I was appalled that I even though the hardware on my wrist was capturing data almost every second, that Fitbit did not allow downloading or even reporting on this data that is MINE and should be easily accessible.  So, after substantial time spent on trial and error at the same time Fitbit is migrating to oAuth2 from 1.1, I perfected a method I now have been using in unpolished form for a couple months.  

When I went looking for the answer of how to accomplish this I was also shocked at how high the demand and number of Fitbit owners that were also screaming for this ability, and how limited the working solutions were at the time.  I scoured and by date could not and still cannot find any working Powershell-based code/module that does what this module does, so yes - my title is bold because I do believe I am so much filling an unsatisfied need for the Fitbit user community that I can safely call this module "the original".  

Even though I offer this solution and code for free by all means feel free to donate using the donate button found at the bottom of this readme.md as well as read and contribute suggestions to my plans to improve it further and add additional features in the future.  Even the smallest donations will not go unnoticed and certainly make continued work to improve this module a bit more fulfilling!  

_Fitbit is a registered trademark and service mark of Fitbit, Inc.  psFitb1t is designed for use with the Fitbit platform.  This product is not put out by Fitbit, and Fitbit does not service or warrant the functionality of this product._




Prerequisites:
--------------

If this is the first execution your browser will open to the Fitbit API URL for you automatically.  The URL is https://dev.fitbit.com.

You must perform the following to set up your own custom Fitbit developer "App" which is simply assigning you a userid and password to access the Fitbit API.

··1.  Navigate to:  https://dev.fitbit.com and either create and account or login and click "Register an app" as shown below:

![Fitbit API screen 1](/images/psfitb1t1.png?raw=true "Fitbit API screen 1")

··2. Fill in the information as shown below.  You may choose any name or description but the remainder of the information should match the values shown here:

![Fitbit API screen 2](/images/psfitb1t2.png?raw=true "Fitbit DEV website prerequisite application setup")

··3. Install psFitb1t module and upon opening `Windows Powershell` and executing your first query with `Get-HRdata -QueryDate "2016-01-01"` you will be presented with the following screen.  You must provide your Fitbit "ClientID" from dev.fitbit.com as this is the actual Fitbit dev site validating your credentials to then provide an access token:

![Fitbit API screen 3](/images/psfitb1t3.png?raw=true "Fitbit ClientID wizard")

··4. Upon successful Fitbit authentication and token receipt, since this is your first run you will now need to provide (and store) your personal Fitbit ClientID and API secret needed for subsequent data queries.  This token will be stored in the registry and will be used for 30 days from the time it was generated on this first run. Upon expiration, the prior step will automatically be triggered to once again authenticate to the Fitbit developer site and re-store another 30 day token:

![psFitb1t setup screen 1](/images/psfitb1t4.png?raw=true "Fitbit DEV website portal login screen")

··4b. *NOTE* Upon successful Fitbit authentication, You must click the "Authorize" button as shown below.  Also note, however, that the "Warning" in this screenshot should NOT be on your screen assuming you set up all the redirect URLs in your application as updated here with HTTPS. This is an old screenshot with the redirectURL of HTTP.  Because nothing ever really returns to an actual application and only the token retrieval is important, either way this warning was erroneous and could be safely ignored.

![psFitb1t setup screen 1](/images/psfitb1t4b.png?raw=true "Fitbit token auth screen")

**Note: If you wish you may manually trigger the token (and storage) process.  Look at the `Set-FitbitOAuthTokens` function I provide.  Passing a -force will wipe the stored registry values and re-validate and can either be run in cmdline mode, or the full Windows GUI forms wizard which is the default option.

![Set-FitbitOAuthTokens execution](/images/psfitb1t5.png?raw=true "Set-FitbitOAuthTokens execution")

**Note2: The ClientID from your Fitbit API app, and the other required values are stored at `HKEY_CURRENT_USER\Software\psFitb1t`

··5. In the psFitb1t module directory (default `C:\Users\<username>\Documents\WindowsPowershell\Modules\psFitb1t`) you should have 2 data files for the above query date - the CSV and the XLSX Excel spreadsheet/chart.




Installation:
-------------

__Run the MSI installer and you are finished__......or if you are feeling brave:

To install manually, copy the psFitb1t.psm1 and psFitb1t.psd files to:

-   `"%PSModulePath%psFitb1t"`

HINT: To manually create the module folder prior to copying:

-   `mkdir "%PSModulePath%psFitb1t"`

Once installed/copied, open Windows Powershell and execute:

-   `Import-Module psFitb1t`

Store your Fitbit API information by executing:

-   `Set-FitbitOAuthTokens`




Examples:
---------

:new: __*New in v1.0.0.2__:  You can now retrieve an entire month of reports!  

###Monthly retrieval:

`C:\> Get-HRmonth -QueryMonth "2016-01"`

This function will automatically check the module/save directory for any existing Excel reports already retrieved and to avoid retrieving will automatically skip existing reports.  It also computes the real calendar days for the month requested.

Please read on below for details of what is generated per individual daily data retrieval.
  
###Daily retrieval:

`C:\> Get-HRdata -QueryDate "2016-01-01"`

Each run can query one 24 hour period for intra-day heartrate data (down to possible 1 second readings).  A successful run for a given 24 hour period with psFitb1t's Get-HRdata command results in the following 2 daily files being created in the module folder:

First, the raw CSV data file with every HR data reading taken by your band in that 24 hour period.  It is this data that psFitb1t uses to create the subsequent Excel spreadsheet and pretty chart, but is also saved with the Excel file to allow you to utilize it in other data applications if needed:

![Get-HRdata Execution CSV data file](/images/psfitb1t6.png?raw=true "Get-HRdata Execution CSV data file")


And Second, psFitb1t does the very heavy lifting of taking that data, importing it into a daily spreadsheet, calculating the minimum, maximum, and average using Excel formulas, and then sets up and formats every aspect of a proper line chart summarizing your daily heartrate with much more accuracy than given by Fitbit on their portal using "summary" data.  psFitb1t does all of this totally automatically without needing any user interaction - simply wait until the command completes and open your Excel file!
**Note:  90% of the command execution time is actually Excel simply charting the thousands of data points for your daily graph - since it is Excel charting, there is no way to further optimize the charting method used.

![Get-HRdata Execution XLSX spreadsheet and chart](/images/psfitb1t7.png?raw=true "Get-HRdata Execution XLSX spreadsheet and chart")


Module specific notes:
----------------------

-   This module by default performs both logging to the console and to a daily execution log.

-   The log folder will be automatically created in the script execution folder.

-   An example of the log generated for a successful execution is:

    -   03/04/2016 08:09:15 :: \[INFO\] :: START - Get-HRdata function execution

    -   03/04/2016 08:09:15 :: \[INFO\] :: START - Connect-OAuthFitbit function execution

    -   03/04/2016 08:09:15 :: \[INFO\] :: START - Loading DOTNET assemblies

    -   03/04/2016 08:09:15 :: \[INFO\] :: FINISH - Loading DOTNET assemblies

    -   03/04/2016 08:09:15 :: \[INFO\] :: START - Retrieving Fitbit API settings from registry

    -   03/04/2016 08:09:15 :: \[INFO\] :: FINISH - Retrieving Fitbit API settings from registry

    -   03/04/2016 08:09:15 :: \[INFO\] :: FINISH - Connect-OAuthFitbit function execution

    -   03/04/2016 08:09:15 :: \[INFO\] :: START - Sending HTTP POST via REST to Fitbit

    -   03/04/2016 08:10:32 :: \[INFO\] :: FINISH - Sending HTTP POST via REST to Fitbit

    -   03/04/2016 08:10:32 :: \[INFO\] :: FINISH - Get-HRdata function execution
  

Changelog:
-------------

-   v 1.0.0.1	:	03-13-2016	:	Initial release
-   v 1.0.0.2	:	03-30-2016	:	Added Get-HRmonth function

*NOTE: changed redirect URL to HTTPS so Fitbit auth screen no longer gives false red warning that anything is "insecure"	

	
Dependencies:
-------------

-   Microsoft Excel MUST be installed or this module cannot currently execute since it utilizes Excel to create the spreadsheet and chart.  Future revisions may allow for data retrieval without automatic spreadsheet and charting.




TODO:
-------------
  1.  Provide a full Windows GUI for all execution

  2.  Provide looping capability in ~~both console~~ and GUI to retrieve multiple days (this can be easily accomplished now using this module in a loop but will automate it within the module in future)

  3.  Add other Fitbit data visualizations

 
 

LICENSE:
-------------
Please see the included LICENSE file.  
  
_THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE._  




Patches/Updates/Bugs/Support:
-----------------------------

This code is a work in progress. The interfaces may change without notice.
Updates, bug fixes, and suggestions are welcome, but please be patient.

I have also linked this repository to Slack. Feel free to send a request for an invite to the Slack team for this project.

Please ping me if you have significant changes in mind, before you do what others have done and simply run off with all my code and make a single line mention in their comments and call it their own bear in mind I work hard to write this code and do it for free. I am all for open source collaboration but please give credit where it is due and avoid unnecessary forks instead of simply contributing or discussing ideas here first or hitting me up on Twitter!

Thanks and more to come soon!

__Collin Chaffin__  
[![Twitter Follow](https://img.shields.io/twitter/follow/collinchaffin.svg?style=social)](https://twitter.com/collinchaffin)




Donations:
-----------------------------

You can support my efforts and every donation is greatly appreciated!  
<a href="https://paypal.me/CollinChaffin"><img src="https://www.paypalobjects.com/en_US/i/btn/btn_donate_LG.gif" alt="[paypal]" /></a>  

