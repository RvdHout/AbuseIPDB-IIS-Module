# AbuseIPDB-IIS-Module

copy the module AbuseIPDBModule.dll your website's /bin directory

in your your website's web.config create

```
  <configSections>
  	<section name="AbuseIPDBModule" type="AbuseIPDB_IIS_Module.Settings" />
  </configSections>
  
  <AbuseIPDBModule Enabled="true" TimeOut="3000" AddHeader="false" MaxScore="30" ApiKey="YOUR_ABUSEIPDB_API_KEY_HERE" LogPath=".\Logs" LogErrors="true" LogHits="true" />
```
   
To debug, build the module using "Debug" build configuration
download and unpack https://docs.microsoft.com/en-us/sysinternals/downloads/debugview
Start as administrator, include filter for [AbuseIPDBModule]
enable Capture Global Win32, other defaults are OK to use
Watch the output when you request pages on your website you enabled the AbuseIPDBModule on

	
# Requirements
- IIS 7 or higher
- Net 4 Application pool running integrated pipeline mode


