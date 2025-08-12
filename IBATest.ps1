$Global:ConfigurationExists = $false; 
$Global:ChiselExists = $false
$Global:Websocket443Available = $false
$Global:Websocket80Available = $false;
$Global:InternetAccessAvailable = $false
$Global:OperatingSystemInfo = "";
$Global:Installed = $false
$Global:AgentName = "";
$Global:TenantURL = "";
$Global:AgentId = "";
$Global:HeaderBreak = "=============================================================================================================================";
$Global:Prereq1Name = "Microsoft.WindowsDesktop.App 8";
$Global:Prereq2Name = "Microsoft.NETCore.App 8";
$Global:Prereq1Installed = $false;
$Global:Prereq2Installed = $false;

[string[]]$Global:DotNetInfo = @();

class RegValue {
  [string]$Name
  [string]$Value
}

class AMSStatus
{
  [string]$Url
  [string]$Protocol
  [boolean]$Accessible
  [string]$Response
}

[RegValue[]]$Global:TLSInfo = @();
[RegValue[]]$Global:Framework4TLSInfo = @();
[RegValue[]]$Global:CipherSuites = @();
[AMSStatus[]]$Global:AMSTests = @();

function IsPreqReqInstalled 
{
  [CmdletBinding()]
  param (
    [string]$RequiredRuntime
  )
  $runtimes = & dotnet --list-runtimes
  foreach ($line in $runtimes) {
    if ($line -like "$RequiredRuntime*") {
      return $true
    }
  }
  return $false
}

function IsInstalled 
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [string]$DisplayName
  )
  $installed = $null -ne (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -eq $DisplayName })
  return $installed
};

function GetInstallPath 
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [string]$DisplayName
  )

  if (IsInstalled($DisplayName)) 
  {
    $Info = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -eq $DisplayName })
    $Path = $Info.InstallLocation
    return $Path;
  }
}

function WriteSetting
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [object]$DisplayName,
    [Parameter(Mandatory)]
    [object]$DisplayValue,
    [Parameter(Mandatory=$false)]
    [object]$addNewLine
  )

  if ($null -eq $addNewLine) 
  {
    $addNewLine = $false
  }
  Write-Host $DisplayName -NoNewline;
  if ($DisplayValue -eq $false)
  {
    Write-Host " $DisplayValue" -ForegroundColor Yellow;
  }
  else 
  {
    if ($DisplayValue -eq $true)
    {
      Write-Host " $DisplayValue" -ForegroundColor Green;
    }
    else
    {
      if ($addNewLine -eq $false)
      {
        $padding = "";
      }
      else
      {
        Write-Host "";
        $padding = "    ";
      }
      if ($DisplayValue -is [array])
      {
        Foreach ($line in $DisplayValue)
        {
          Write-Host "$padding $line" -ForegroundColor Gray;
        }
      }
      else
      {
        Write-Host "$padding $DisplayValue" -ForegroundColor White;
      }
    }
  }
}

function OutputRegistryValues
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [RegValue[]]$list
  )

  $padding = 120;
  $padChar = '.';

  foreach ($item in $list) 
  {
    Write-Host "$($item.Name)".PadRight($padding,$padChar) -NoNewline -ForegroundColor Green;
    Write-Host " $($item.Value)" -ForegroundColor Yellow;
  }
}

function OutputAmsStatusValues
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [AMSStatus[]]$list
  )

  $padding = 60;
  $padChar = '.';

  foreach ($item in $list) 
  {
    Write-Host "$($item.Url)::$($item.Protocol)".PadRight($padding,$padChar) -NoNewline -ForegroundColor White;
    if ($item.Accessible -eq $true) 
    {
      Write-Host "$($item.Accessible)" -ForegroundColor Green;
    }
    else
    {
      Write-Host "$($item.Accessible)" -NoNewline -ForegroundColor Yellow;
      Write-Host " Error: $($item.Response)" -ForegroundColor DarkYellow;
    }
  }
}

function getDotNetInfo
{
  $info = (dotnet --info) | Out-String
  return $info.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
}

function OutputStateOfSystem
{
  $padding = 70;
  $padChar = '.';

  Write-Host "";
  Write-Host($Global:HeaderBreak);
  Write-Host "Test Results";
  Write-Host($Global:HeaderBreak);

  WriteSetting $Global:Prereq1Name.PadRight($padding,$padChar) $Global:Prereq1Installed;
  WriteSetting $Global:Prereq2Name.PadRight($padding,$padChar) $Global:Prereq2Installed;

  if (!$Installed) 
  {
    WriteSetting "Product installed".PadRight($padding,$padChar) $false;
    WriteSetting "Internet Connection Available".PadRight($padding,$padChar) $InternetAccessAvailable;
    WriteSetting "Websocket 443 Connection Possible".PadRight($padding,$padChar) $Websocket443Available;
    #WriteSetting "Websocket  80 Connection Possible".PadRight($padding,$padChar) $Websocket80Available;
  }
  else
  {
    WriteSetting "Chisel executable avaialble".PadRight($padding,$padChar) $ChiselExists;
    WriteSetting "Internet Connection Available".PadRight($padding,$padChar) $InternetAccessAvailable;
    WriteSetting "Configuration avaialble".PadRight($padding,$padChar) $ConfigurationExists;
    if ($ConfigurationExists)
    {
      # details about current configuration
      WriteSetting "Tenant URL".PadRight($padding,$padChar) $TenantURL $false;
      WriteSetting "Agent Name".PadRight($padding,$padChar) $AgentName $false;
    }
    WriteSetting "Websocket 443 Connection Possible".PadRight($padding,$padChar) $Websocket443Available;
    #WriteSetting "Websocket  80 Connection Possible".PadRight($padding,$padChar) $Websocket80Available;
  }

  WriteSetting "HostName".PadRight($padding,$padChar) $env:COMPUTERNAME $false;
  WriteSetting "Operating system info".PadRight($padding,$padChar) $OperatingSystemInfo $false;

  # Optionally, show the prereq status again in DotNet Versions section:
  WriteSetting "DotNet Versions".PadRight($padding,$padChar) $DotNetInfo $true;
  WriteSetting $Global:Prereq1Name.PadRight($padding,$padChar) $Global:Prereq1Installed;
  WriteSetting $Global:Prereq2Name.PadRight($padding,$padChar) $Global:Prereq2Installed;

  WriteSetting "DotNet 2.x TLS information".PadRight($padding,$padChar) "";
  OutputRegistryValues $TLSInfo;
  WriteSetting "DotNet 4.x TLS information".PadRight($padding,$padChar) "";
  OutputRegistryValues $Framework4TLSInfo;
  WriteSetting "TLS Cipher Suite".PadRight($padding,$padChar) "";
  OutputRegistryValues $CipherSuites;

  WriteSetting "AMS URLs Accessible".PadRight($padding,$padChar) "";
  OutputAmsStatusValues $AMSTests
  Write-Host "" -ForegroundColor Cyan;
  Write-Host "Report complete" -ForegroundColor Cyan;
}

function InternetConnection
{
  #Test web access

  try
  {
    #can we access the google dns?
    $j = Test-NetConnection 8.8.8.8 -InformationLevel "Detailed"
    $availByIP = $j.PingSucceeded;
    $j = Test-NetConnection Google.com -InformationLevel "Detailed"
    $availByDNS = $j.PingSucceeded;
    return $availByIP -and $availByDNS;
  }
  catch
  {
    return $false;
  }
}

function ReadConfiguration
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [string]$ConfigFile
  )

  $configContent = Get-Content $ConfigFile -Raw;
  $settings = $configContent | ConvertFrom-Json 
  $Global:AgentName = $settings.Name;
  $Global:AgentId = $settings.Id;
  $Global:TenantURL = $settings.TenantUrl;
}

function getRootDomain
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [string]$URL
  )

  $parts=$URL.Trim().Split('.');
  $partLen=$parts.Length-1;

  return $parts[$partLen-1]+"."+$parts[$partLen];
}

function WebsocketConnection
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [string]$URL
  )

  $key="x3JJHMbDL1EzLkh9GBhXDw==";

  #if we had a way to get a valid Bearer token from the cognito configuration, we might be able to actually test the AMS URI
  #but, that won't be possible due to the encryption on the Cognito.bin file
  # $dhost=getRootDomain($URL);
  # $uriPart=[string]::Format("https://ams.ia.{0}",$dhost)
  #this should be the URL for an agent pollConfig request
  # $uri=[string]::Format("{0}/agents/{1}:pollConfig",$uriPart,$Global:AgentId)
  # Write-Host("connecting to: $uri");
  # $method="post";
  # $body = "{}";
  # $expectedStatusCode = 401; #should get unauthorized from API gateway
  # $Token="invalid"; #we don't currently have a way to generate this via cognito and powershell
  #since we are not doing a WS upgrade with this header (we don't get a response back from AMS becase we are unauthorised) 
  #this may not change the protocol specifically - it will use "regular SSL" which might not be blocked anyway
  # $head=@{"Authorization"="`"Bearer $($Token)`""};

  #We could use the "new" Websocket.org - `echo.websocket.events` site for testing the websocket via https
  #this will at least let us know the CLIENT can reach out via WEBSOCKET to a remote site over https/443 and WS protocol or if a firewall is blocking it
  $dhost = "echo.websocket.events";
  $uri = "${URL}://"+$dhost+"/.ws";
  if ($url.ToLower() -eq "http")
  {
    $uriPart = $uri.Replace("http:","https:");
  }
  else
  {
    $uriPart = $uri;
  }
  $method = "get";
  $expectedStatusCode = 101;
  #connect to websocket an "upgrade" the http(s) connection to websocket protocol
  #if successful, should return 101 "upgrade" response
  $head=@{"Connection"="Upgrade";"Upgrade"="websocket";"Host"=$dhost;"Origin"=$uriPart;"Sec-WebSocket-Key"=$key;"Sec-WebSocket-Version"=13};

  try
  {
    #force an HTTP version if needed (requires http1.1 as 2.x doesn't support Upgrade header?)
    #-HttpVersion Version11 - current PS doesn't support this, need at least 7.3.0.preview.1
    #default psversion on Windows 11 - 5.1.22000.xxx

    #Force a TLS version if needed
    #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ($method -eq "get")
    {
      $response = Invoke-WebRequest -Uri $uri -Headers $head -TimeoutSec 15 -UseBasicParsing -ContentType "application/json";
    }
    else
    {
      $response = Invoke-WebRequest -Uri $uri -Headers $head -TimeoutSec 15 -UseBasicParsing -ContentType "application/json" -Method Post -Body $body;
    }
    $statusCode = $Response.StatusCode;
  }
  catch
  {
    #Write-Host($_.Exception);
    $statusCode=$_.Exception.Response.StatusCode.value__
  }

  #101 is the status code for "Switching Protocols" that the WS should respond with when making a connection
  return $statusCode -eq $expectedStatusCode;
}

function OsInfo
{
  $reg = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
  $osInfo = (Get-ItemProperty -Path Registry::$reg);
  $os = $osInfo.ProductName;
  $build = $osInfo.BuildLab;
  $display = $osInfo.DisplayVersion;
  $ver = $osInfo.CurrentVersion;

  return "$os -- $build -- $display -- ver: $ver";
}

function GetAllRegistryValuesFromPath
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [string]$path
  )

    [RegValue[]]$result = @()
    $excludeProperties = @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")

    $properties = Get-ItemProperty -Path $path
    foreach ($property in $properties.PSObject.Properties) 
    {
      if ($excludeProperties -notcontains $property.Name)
      {
        $result += [RegValue]@{
            Name = $path+"\"+$property.Name
            Value = $property.Value
        }
      }
    }
    if ($null -eq $properties)
    {
        $result += [RegValue]@{
            Name = $path
            Value = "no values available"
        }
    }
    return $result
}

function RecurseRegistryForValues
{
  [CmdletBinding()]
  param (
    [Parameter(Mandatory)]
    [string]$path
  )

    [RegValue[]]$properties = GetAllRegistryValuesFromPath($path);

    $subkeys = Get-ChildItem $path -Recurse
    foreach ($key in $subkeys) {
        [RegValue[]]$props = GetAllRegistryValuesFromPath($key.PSPath);
        if ($props)
        {
          foreach ($item in $props) 
          {
            if ($item.Name -notContains $key)
            {
              $properties += [RegValue]@{
                Name = $item.Name
                Value = $item.Value
              }
            }
          }
        }
    }
    return $properties;
}

function InvokeTlsRequest 
{
  [CmdletBinding()]
  [OutputType([AMSStatus])]
  param(
      [Parameter(Mandatory)]
      [string]$Uri,
      [Parameter(Mandatory)]
      [string]$Protocol
  );


  if ($null -eq $Protocol -or $Protocol.Trim() -eq "")
  {
    $Protocol = "Tls12";
  }

  $res = New-Object -TypeName 'AMSStatus';
  $res.Url = $Uri;
  $res.Accessible = $true;
  $res.Response = "";
  $res.Protocol = $Protocol;

  try
    {
      [BasicHtmlWebResponseObject] $response = Invoke-WebRequest -Uri $Uri -SslProtocol $Protocol -Method "GET";
      $res.Response = $response.StatusCode;
    }
    catch 
    {
      $NegotiationFailed = -2147467259;
      $msg = $_
      #Write-Host $msg;
      if ($msg.ErrorDetails.Message -like "*Missing Authentication Token*")
      {
        $res.Response = $msg.Exception.Message
      }
      else 
      {
        $res.Accessible = $false;
        if ($NegotiationFailed -eq $msg.Exception.InnerException.InnerException.ErrorCode)
        {
          # if the server doesn't have the same cipher algorithms available or doesn't support the TLS version,
          # then we get `The SSL connection could not be established, see inner exception.`
          # which ultimately means that the protocol negotiation failed
          # this is typically this message
          # Negotiation Failed -> `The client and server cannot communicate, because they do not possess a common algorithm.`
          $res.Response = $msg.Exception.InnerException.InnerException.Message;
        }
        else 
        {
          $res.Response = $msg.Exception.Message;
        }
      }
    }
    return $res;
}
function TestAMS
{
  [string[]]$Services = @("https://ams.ia.rapididentity.com/", "https://ams.ia.us001-rapididentity.com/", "https://ams.ia.us002-rapididentity.com/", "https://ams.ia.us003-rapididentity.com/", "https://ams.ia.eu001-rapididentity.com/");
  #Note that as of 06/23/2023 - AMS Server does NOT support TLS13, but may in some future update
  #at this time we expect errors: `The SSL connection could not be established, see inner exception.`
  [string[]]$protocols = @("Tls13", "Tls12", "Tls11", "Tls");
  [AMSStatus[]]$results = @();
  foreach ($protocol in $protocols)
  {
    foreach ($Uri in $Services)
    {
      #Write-Host "service: $Uri -> $protocol"
      $results += InvokeTlsRequest $Uri $protocol;
    };
  }
  return $results;
}

#Powershell 7.1+ is required for testing TLS13 support
function isPSVersion7
{
  return $PSVersionTable.PSVersion -like "7.*"
}

function installPSVersion7
{
  Invoke-Expression "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI"
}

function Test
{
  $isRunningPS7 = isPSVersion7
  if ($isRunningPS7 -eq $false)
  {
    Write-Host "Script was not executed with Powershell 7.1 or it may not be installed.  Current version is" $PSVersionTable.PSVersion -ForegroundColor Yellow;
    Write-Host "Download and install Powershell 7.1 or above?" -NoNewline -ForegroundColor Yellow;
    $userResponse = (Read-Host " [Y/N]").ToLower() -eq "y";
    if ($userResponse -eq $true)
    {
      Write-Host  "...download and install in progress..." -ForegroundColor Cyan;
      installPSVersion7;
      Write-Host "Re-run this script using newly installed powershell command processor" -ForegroundColor Yellow;
      # installer will put the path to powershell in the $env:path - however, since this instance is currently
      # executing without it, we can't directly execute the new shell after the install - a new instance of the shell
      # must be started to get the updated environment
    }
    else 
    {
      #user may have just invoked the wrong processor - allow the choice to switch to the "already installed update"
      Write-Host "Attempt to run with Powershell 7+?" -NoNewline -ForegroundColor Yellow;
      $userResponse = (Read-Host " [Y/N]").ToLower() -eq "y";
      if ($userResponse -eq $true)
      {
        pwsh.exe -File $MyInvocation.PSCommandPath
      }
      else 
      {
        Write-Host "Re-run this script using Powershell 7.1 or above" -ForegroundColor White;
      }
    }
    return;
  }
  
  $software = "Identity Bridge Agent";
  Write-Host($Global:HeaderBreak);
  Write-Host("Beginning test for",$software);
  Write-Host($Global:HeaderBreak);

  # Check both prerequisites at the start
  $Global:Prereq1Installed = IsPreqReqInstalled -RequiredRuntime $Global:Prereq1Name
  $Global:Prereq2Installed = IsPreqReqInstalled -RequiredRuntime $Global:Prereq2Name

  $Global:OperatingSystemInfo = OsInfo;

  Write-Host("Testing installation");
  Write-Host("Testing internet connection");
  $Global:InternetAccessAvailable = InternetConnection;

  Write-Host("Testing web socket connection over 443");
  $Global:Websocket443Available = WebsocketConnection("https");

  # Only test port 80 if 443 failed
  if (-not $Global:Websocket443Available) {
    Write-Host("Testing web socket connection over 80 (Optional)");
    $Global:Websocket80Available = WebsocketConnection("http");
  } else {
    $Global:Websocket80Available = $null
  }

  Write-Host("Retrieving DotNet Framework information");
  $Global:DotNetInfo = getDotNetInfo;
  Write-Host("Retrieving DotNet TLS info");
  $Global:Framework4TLSInfo = GetAllRegistryValuesFromPath("HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319"); 
  $Global:TLSInfo = GetAllRegistryValuesFromPath("HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727");
  Write-Host("Retrieving Cipher Suite Info");
  $Global:CipherSuites = RecurseRegistryForValues("HKLM:SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers");
  Write-Host("Testing connection to AMS Hosts");
  $Global:AMSTests = TestAms;

  $path = GetInstallPath($software);
  if ($path) {
    $Global:Installed = $true;
    Write-Host("Testing file paths");
    $agentStatePath = Join-Path -Path $path -ChildPath "AgentState.json";
    $chiselPath = Join-Path -Path $path -ChildPath "chisel.exe";

    $Global:ConfigurationExists = [System.IO.File]::Exists($agentStatePath);
    $Global:ChiselExists = [System.IO.File]::Exists($chiselPath);
    if ($Global:ConfigurationExists)
    {
      Write-Host("Loading configuration");
      ReadConfiguration($agentStatePath);
    }
  } 

  OutputStateOfSystem;
}

#main
Test;
