$ErrorActionPreference = "Stop"

class vCloudException : System.Exception
{
    [string]$vCloudMessage
    vCloudException([string]$v,[exception]$e) : base($e.Message, $e) {
        $this.vCloudMessage = $v
    }
}

function Write-vCloudException {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.ErrorRecord]
        $exception
    )
        if($null -eq $exception.Exception.Response) {
            $responseBody = "UnCategorized"
        }
        else {
            $result = $exception.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($result)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd() | ConvertFrom-Json
        }
        Throw [vCloudException]::new($responseBody, $exception.Exception)
}

function Write-Log {
    [CmdletBinding()]
    param (
        # Log message
        [ValidateNotNullOrEmpty()]
        [String]
        $log,
        [Switch]
        $output

    )

    begin {

    }

    process {
        $message = "$(Get-Date -Format 'yyyyMMddHHmmss') -- $((Get-PSCallStack | Select-Object FunctionName -Skip 1 -First 1).FunctionName) -- $log"
        if($output) {
            Write-Output $message
        }
        else {
            Write-Verbose -Message $message
        }
    }

    end {

    }
}

function Approve-InsecureEndpoints {
    param (

    )

    begin {

    }

    process {
        try {
            add-type @"
                using System.Net;
                using System.Security.Cryptography.X509Certificates;
                public class TrustAllCertsPolicy : ICertificatePolicy {
                    public bool CheckValidationResult(
                        ServicePoint srvPoint, X509Certificate certificate,
                        WebRequest request, int certificateProblem) {
                        return true;
                    }
                }
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
            [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
        catch {
            $exception = $PSItem | Select-Object * | Format-Custom -Depth 1 | Out-String
            Throw $exception
        }
    }

    end {

    }
}

function New-VDCToken {
    param (
        # Username
        [ValidateNotNullOrEmpty()]
        [String]
        $user,
        # Password
        [ValidateNotNullOrEmpty()]
        [String]
        $pass,
        # VCD Base Url
        [ValidateNotNullOrEmpty()]
        [String]
        $vcdUrl
    )

    begin {

    }

    process {
        try {
            $apiUrl = $vcdUrl + "/cloudapi/1.0.0/sessions/provider"
            $pair = "$($user):$($pass)"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
            $base64 = [System.Convert]::ToBase64String($bytes)
            $headers = @{
                 Accept = "application/json;version=35.0"
                 Authorization = "Basic $base64"
            }
            Write-Log -Log "Created headers: $($headers | Out-String)"
            $response = Invoke-WebRequest -Method Post -Headers $headers -Uri $apiUrl -UseBasicParsing
            Write-Log -Log "Received response: $response"
            return $response.Headers
        }
        catch {
            Throw $PSItem
        }
    }

    end {

    }
}

function Get-VDCEdgeGateway {
    [CmdletBinding()]
    param (
        # Token
        [ValidateNotNullOrEmpty()]
        [String]
        $token,
        # VCD Base Url
        [ValidateNotNullOrEmpty()]
        [String]
        $vcdUrl,
        # Context
        [String]
        $context

    )

    begin {

    }

    process {
        try {
            $apiUrl = $vcdUrl + "/cloudapi/1.0.0/edgeGateways"
            if(-not [String]::IsNullOrEmpty($context)) {
                $apiUrl += "?page=1&pageSize=10&filterEncoded=true&filter=((status==REALIZED;ownerRef.id==$context))"
            }
            $headers = @{
                 Accept = "application/json;version=35.0"
                 Authorization = "Bearer $token"
            }
            Write-Log -Log "Created headers: $($headers | Out-String)"
            $response = Invoke-RestMethod -Method Get -Headers $headers -Uri $apiUrl -UseBasicParsing
            Write-Log -Log "Received response: $($response| ConvertTo-Json -Depth 10 -Compress)"
            return $response
        }
        catch {
            Write-vCloudException -exception $PSItem
        }
    }

    end {

    }
}

function New-VDCEdgeGateway {
    [CmdletBinding()]
    param (
        # Token
        [ValidateNotNullOrEmpty()]
        [String]
        $token,
        # VCD Base Url
        [ValidateNotNullOrEmpty()]
        [String]
        $vcdUrl,
        # Body
        [ValidateNotNullOrEmpty()]
        [String]
        $body

    )

    begin {

    }

    process {
         try {   
            Write-Log -log "Creating new Edge Gateway --> $(($body | ConvertFrom-Json).name)" -output
            $apiUrl = $vcdUrl + "/cloudapi/1.0.0/edgeGateways"
            $headers = @{
                 Accept = "application/json;version=35.0"
                 Authorization = "Bearer $token"
            }
            Write-Log -Log "Created headers: $($headers | Out-String)"
            Write-Log -Log "Created body: $body"
            $resp = Invoke-WebRequest -Method POST -Headers $headers -Uri $apiUrl -UseBasicParsing -Body $body -ContentType "application/json"
            Write-Log -Log "Received response: $($resp | ConvertTo-Json -Depth 2 -Compress)"
            Write-Log -log "Created new Edge Gateway --> $(($body | ConvertFrom-Json).name)" -output
        }
        catch {
            Write-vCloudException -exception $PSItem
        }
    }

    end {

    }
}

function Get-VDC {
    [CmdletBinding()]
    param (
        # Token
        [ValidateNotNullOrEmpty()]
        [String]
        $token,
        # VCD Base Url
        [ValidateNotNullOrEmpty()]
        [String]
        $vcdUrl,
        [String]
        $name

    )

    begin {

    }

    process {
        try {
            $apiUrl = $vcdUrl + "/api/query?type=adminOrgVdc&format=records&page=1&pageSize=15&filterEncoded=true&filter=(isEnabled==true)"
            $headers = @{
                 Accept = "application/*+json;version=35.0;multisite=global"
                 Authorization = "Bearer $token"
            }
            Write-Log -Log "Created headers: $($headers | Out-String)"
            $response = (Invoke-RestMethod -Method Get -Headers $headers -Uri $apiUrl -UseBasicParsing).record
            
            if(-not [String]::IsNullOrEmpty($name) ) {
                $response = $response | where-object {$_.name -eq $name}
            }
            Write-Log -Log "Received response: $($response | ConvertTo-Json -Depth 10 -Compress)"
            return $response
        }
        catch {
            Write-vCloudException -exception $PSItem
        }
    }

    end {
    
    }
}

function Get-VDCOrgNetwork {
    [CmdletBinding()]
    param (
        # Token
        [ValidateNotNullOrEmpty()]
        [String]
        $token,
        # VCD Base Url
        [ValidateNotNullOrEmpty()]
        [String]
        $vcdUrl,
        # VCD Owner Ref ID
        [ValidateNotNullOrEmpty()]
        [String]
        $context

    )

    begin {

    }

    process {
        try {
            $apiUrl = $vcdUrl + "/cloudapi/1.0.0/orgVdcNetworks?filterEncoded=true&filter=((ownerRef.id==$context);(_context==includeAccessible))&links=true"
            $headers = @{
                 Accept = "application/json;version=35.0"
                 Authorization = "Bearer $token"
            }
            Write-Log -Log "Created headers: $($headers | Out-String)"
            $response = Invoke-RestMethod -Method Get -Headers $headers -Uri $apiUrl -UseBasicParsing
            Write-Log -Log "Received response: $($response| ConvertTo-Json -Depth 10 -Compress)"
            return $response
        }
        catch {
            Write-vCloudException -exception $PSItem
        }
    }

    end {

    }
}

function Get-VDCExtNetworks {
    [CmdletBinding()]
    param (
        # Token
        [ValidateNotNullOrEmpty()]
        [String]
        $token,
        # VCD Base Url
        [ValidateNotNullOrEmpty()]
        [String]
        $vcdUrl,
        # VCD Owner Ref ID
        [ValidateNotNullOrEmpty()]
        [String]
        $context

    )

    begin {

    }

    process {
        try {
            $apiUrl = $vcdUrl + "/cloudapi/1.0.0/externalNetworks?page=1&pageSize=15&filterEncoded=true&filter=(_context==$context;dedicatedEdgeGateway.id==null;networkBackings.values.backingTypeValue==NSXT_TIER0)&sortAsc=name&links=true" #backingType for version 34
            $headers = @{
                 Accept = "application/json;version=35.0"
                 Authorization = "Bearer $token"
            }
            Write-Log -Log "Created headers: $($headers | Out-String)"
            $response = Invoke-RestMethod -Method Get -Headers $headers -Uri $apiUrl -UseBasicParsing
            Write-Log -Log "Received response: $($response| ConvertTo-Json -Depth 10 -Compress)"
            return $response
        }
        catch {
            Write-vCloudException -exception $PSItem
        }
    }

    end {

    }
}

function Get-VDCAvailableNetworkRanges {
    [CmdletBinding()]
    param (
        # Token
        [ValidateNotNullOrEmpty()]
        [String]
        $token,
        # VCD Base Url
        [ValidateNotNullOrEmpty()]
        [String]
        $vcdUrl,
        # VCD Owner Ref ID
        [ValidateNotNullOrEmpty()]
        [String]
        $context

    )

    begin {

    }

    process {
        try {
            $apiUrl = $vcdUrl + "/cloudapi/1.0.0/externalNetworks/$context/availableIpAddresses"
            $headers = @{
                 Accept = "application/json;version=35.0"
                 Authorization = "Bearer $token"
            }
            Write-Log -Log "Created headers: $($headers | Out-String)"
            $response = Invoke-RestMethod -Method Get -Headers $headers -Uri $apiUrl -UseBasicParsing
            Write-Log -Log "Received response: $($response| ConvertTo-Json -Depth 10 -Compress)"
            return $response
        }
        catch {
            Write-vCloudException -exception $PSItem
        }
    }

    end {

    }
}

function Get-VDCEdgeClusters {
    [CmdletBinding()]
    param (
        # Token
        [ValidateNotNullOrEmpty()]
        [String]
        $token,
        # VCD Base Url
        [ValidateNotNullOrEmpty()]
        [String]
        $vcdUrl,
        # VCD Owner Ref ID
        [ValidateNotNullOrEmpty()]
        [String]
        $context

    )

    begin {

    }

    process {
        try {
            $apiUrl = $vcdUrl + "/cloudapi/1.0.0/nsxTResources/edgeClusters?filterEncoded=true&filter=(_context==$context)"
            $headers = @{
                 Accept = "application/json;version=35.0"
                 Authorization = "Bearer $token"
            }
            Write-Log -Log "Created headers: $($headers | Out-String)"
            $response = Invoke-RestMethod -Method Get -Headers $headers -Uri $apiUrl -UseBasicParsing
            Write-Log -Log "Received response: $($response| ConvertTo-Json -Depth 10 -Compress)"
            return $response
        }
        catch {
            Write-vCloudException -exception $PSItem
        }
    }

    end {

    }
}

function New-VDCOrgNetwork {
    [CmdletBinding()]
    param (
        # Token
        [ValidateNotNullOrEmpty()]
        [String]
        $token,
        # VCD Base Url
        [ValidateNotNullOrEmpty()]
        [String]
        $vcdUrl,
        # Body
        [ValidateNotNullOrEmpty()]
        [String]
        $body

    )

    begin {

    }

    process {
         try {   
            Write-Log -log "Creating new Organization Network --> $(($body | ConvertFrom-Json).name)" -output
            $apiUrl = $vcdUrl + "/cloudapi/1.0.0/orgVdcNetworks"
            $headers = @{
                 Accept = "application/json;version=35.0"
                 Authorization = "Bearer $token"
            }
            Write-Log -Log "Created headers: $($headers | Out-String)"
            Write-Log -Log "Created body: $body"
            $response = Invoke-WebRequest -Method POST -Headers $headers -Uri $apiUrl -UseBasicParsing -Body $body -ContentType "application/json"
            Write-Log -Log "Received response: $($response | ConvertTo-Json -Depth 2 -Compress)"
            Write-Log -log "Created new Organization Network --> $(($body | ConvertFrom-Json).name)" -output
        }
        catch {
            Write-vCloudException -exception $PSItem
        }
    }

    end {

    }
}

function New-VDCNatRule {
    [CmdletBinding()]
    param (
        # Token
        [ValidateNotNullOrEmpty()]
        [String]
        $token,
        # VCD Base Url
        [ValidateNotNullOrEmpty()]
        [String]
        $vcdUrl,
        # Body
        [ValidateNotNullOrEmpty()]
        [String]
        $context,
        # Body
        [ValidateNotNullOrEmpty()]
        [String]
        $body
    )

    begin {

    }

    process {
         try {   
            Write-Log -Log "Creating new NAT rule --> $(($body | ConvertFrom-Json).name)" -output
            $apiUrl = $vcdUrl + "/cloudapi/1.0.0/edgeGateways/$context/nat/rules"
            $headers = @{
                 Accept = "application/json;version=35.0"
                 Authorization = "Bearer $token"
            }
            Write-Log -Log "Created headers: $($headers | Out-String)"
            Write-Log -Log "Created body: $body"
            $response = Invoke-WebRequest -Method POST -Headers $headers -Uri $apiUrl -UseBasicParsing -Body $body -ContentType "application/json"
            Write-Log -Log "Received response: $($response | ConvertTo-Json -Depth 2 -Compress)"
            Write-Log -Log "Created new NAT rule --> $(($body | ConvertFrom-Json).name)" -output
        }
        catch {
            Write-vCloudException -exception $PSItem
        }
    }

    end {

    }
}


# Export only the functions using PowerShell standard verb-noun naming.
# Be sure to list each exported functions in the FunctionsToExport field of the module manifest file.
# This improves performance of command discovery in PowerShell.
Export-ModuleMember -Function *-*
