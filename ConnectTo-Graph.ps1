<#
.SYNOPSIS
connect to the Graph environment and return the connection as an object
containing a token and it's lifecycle (expiry date/time)
.LINK
https://tech.nicolonsky.ch/explaining-microsoft-graph-access-token-acquisition/
#>
[cmdletbinding()]
param(
    [Parameter()]$TenantID,
    [Parameter()]$AppRegistrationID,
    [Parameter()]$AppSecret,
    [Parameter()]$CertificatePath,
    [Parameter(DontShow, ValueFromRemainingArguments)]$Superfluous
)

process {
    Write-Verbose -Message "Trying to get a REST token to be used for a connection to MS Graph..."
    try {
        $GraphConnection = Invoke-RestMethod @PostSplat
        Write-Verbose -Message "Token is acquired and remains valid until $((Get-Date).AddSeconds($GraphConnection.expires_in))"
    }
    catch { Write-Error -Message "ERROR: $($_.Exception)" }
}

begin {
    $AuthUri = "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token"
    if ($CertificatePath) {
        try { 
            $Certificate = Get-Item $CertificatePath
            $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash()) -replace '\+', '-' -replace '/', '_' -replace '=' 
        }
        catch { Write-Error -Message "Error retrieving certificate: $($CertificatePath), exiting script..."; exit }
        $JWTHeader = @{
            alg = "RS256"
            typ = "JWT"
            x5t = $CertificateBase64Hash 
        }
        $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
        $Now = (Get-Date).ToUniversalTime()
        $NotBefore = [math]::Round((New-TimeSpan -Start $StartDate -End $Now).TotalSeconds, 0)
        $JWTExpiration = $NotBefore + 120 # add 2 minutes
        $JWTPayLoad = @{
            aud = $AuthUri
            exp = $JWTExpiration
            iss = $AppRegistrationID
            jti = [guid]::NewGuid()
            nbf = $NotBefore
            sub = $AppRegistrationID
        }
        $EncodedHeader = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json)))
        $EncodedPayload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json)))
        $JWT = [System.Text.Encoding]::UTF8.GetBytes($EncodedHeader + "." + $EncodedPayload)
        $PrivateKey = $Certificate.PrivateKey
        $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
        $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
        $Signature = [Convert]::ToBase64String($PrivateKey.SignData($JWT, $HashAlgorithm, $RSAPadding)) -replace '\+', '-' -replace '/', '_' -replace '='
        $JWT = $JWT + "." + $Signature
        $Body = @{
            Grant_Type            = "client_credentials"
            Client_Id             = $AppRegistrationID
            Client_Assertion      = $JWT
            Client_Assertion_Type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            Scope                 = "https://graph.microsoft.com/.default"
        }
        $script:PostSplat = @{
            ContentType = 'application/x-www-form-urlencoded'
            Method      = 'POST'
            Body        = $Body
            Uri         = $AuthUri
            Headers     = @{ Authorization = "Bearer $JWT" }
        }
    }
    else {
        $body = @{ 
            Grant_Type    = "client_credentials"
            Client_Id     = $AppRegistrationID
            Client_Secret = $AppSecret
            Scope         = "https://graph.microsoft.com/.default"
        }
        $script:PostSplat = @{
            Uri    = $AuthUri
            Method = 'POST'
            Body   = $Body
        }
    }
}

end { return $GraphConnection }
