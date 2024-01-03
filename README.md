# Graph automation for Office 365 tenant management

first function to call is **ConnectTo-Graph** as to retrieve token when connecting to MG Graph SDK (in Powershell):

one way to it is dot source it like this (if in the same directory):

`$MGConnection = & "$PSScriptRoot\ConnectTo-Graph" -TenantID $TID -AppRegistrationID $AppRegID -AppSecret $Secret`

    if ($MGConnection) {
        $ExpiresIn = $((Get-Date).AddSeconds($MGConnection.expires_in))
        Write-Host "Token is acquired and valid until $($ExpiresIn)")
        $MGHeader = @{ 'Authorization' = "Bearer $MGConnection.access_token" }
        $AccessToken = ($MGConnection.access_token | ConvertTo-SecureString -AsPlainText -Force)
        Connect-MgGraph -AccessToken $AccessToken
    	  }

and `$MGHeader` can then be (re)used for authentication on REST method calls:

`Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/domains" -Headers $MGHeader`

This way there are no dependencies or need for MSAL libraries or AZ- modules to use the Graph.

> warning: tokens for apps last only 1 hour, after that you need to call the function again, 
> a refresh or renew of the app token is not possible (at this time or AFAIK)
