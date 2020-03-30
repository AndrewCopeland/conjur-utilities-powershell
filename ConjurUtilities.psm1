Import-Module ./CyberarkConjur.psm1

Function Replace-KeyValue()
{
    param(
        $FilePath,
        $ReplaceDictionary
    )
    $content = Get-Content -Path "$filePath" -Raw
    Write-Verbose "Content of $FilePath  `n$content"

    foreach ($kv in $ReplaceDictionary.GetEnumerator()) 
    {
        Write-Verbose -Message "Replacing '$($kv.Name)' with '$($kv.Value)'"
        $content = $content -replace  "$($kv.Name)", "$($kv.Value)"
    }
    Write-Output $content
}

Function Get-EpochTime()
{
    $date1 = Get-Date -Date "01/01/1970"
    $date2 = Get-Date
    $epochTime = (New-TimeSpan -Start $date1 -End $date2).TotalSeconds
    Write-Output $epochTime
}

<#
.SYNOPSIS

Create a Conjur policy that representes an application

.DESCRIPTION

Create a Conjur policy that represents an application and the safes associated with this application.

.PARAMETER AppName
The name of the application being created.

.PARAMETER VaultName
The name of the vault configured within conjur.
Mandatory when adding this app to a safes.
example secret: vaultName/lobUser/safeName/cyberark-object-name/password

.PARAMETER LobUser
The name of the LOB user configured within conjur.
Mandatory when adding this app to a safes.
example secret: vaultName/lobUser/safeName/cyberark-object-name/password

.PARAMETER AdminSafes
The name of the Cyberark Safe this application will be the owner of in conjur.
When an app is admin of a safe it has the ability to create, update and retrieve variable secrets within conjur.

.PARAMETER ConsumerSafes
The name of the Cyberark Safe this application will have retrieve secret access too.
When an app is a consumer of a safe it only has the ability to list and retrieve variable secrets within conjur.

.PARAMETER Authenticator
The authenticator this application will have access too. 
An example would be 'authn-iam/test'. 
Remember that this authenticator must be enabled and configured on the conjur appliance. 
To check an authenticators status perform 'Invoke-RestMethod -Uri "https://<conjur appliance url>/info"'.

.PARAMETER CreateNamespace
If a namespace should be created for this application.
The namespace will have the same name as the application.
The application will have the ability to load conjur policy within this namespace, 
essentially allowing this application to create any conjur resource.

.PARAMETER ConjurTemplateFolder
The conjur template folder path.
This folder is expected to have the following files: 
app-template.yml, authn-template.yml, namespace-template.yml, 
safe-admin-template.yml and safe-consumer-template.yml

.INPUTS

None. You cannot pipe objects to Get-ConjurAppPolicy.

.OUTPUTS

System.String. The content of the conjur policy generated for this application

.EXAMPLE

Get-ConjurAppPolicy -AppName app1
### --- policy for app1 ---
# create application
- !host app1
### --- end policy for app1 ---

.EXAMPLE

Get-ConjurAppPolicy -AppName app1 -Authenticator "authn-iam/test"
### --- policy for app1 ---
# create application
- !host app1

# granting 'app1' ability to use 'authn-iam/test'
- !grant
  role: !group conjur/authn-iam/test/apps
  member: !host app1
### --- end policy for app1 ---

.EXAMPLE

Get-ConjurAppPolicy -AppName app1 -Authenticator "authn-iam/test" -VaultName "vaultName" -LobUser "lobUser" -ConsumerSafes $("ORACLE_CLOUD_DB", "COUCH_PREM_DB")
### --- policy for app1 ---
# create application
- !host app1

# granting 'app1' ability to use 'authn-iam/test'
- !grant
  role: !group conjur/authn-iam/test/apps
  member: !host app1

# granting 'app1' retrieve only privileges to safe 'ORACLE_CLOUD_DB'
- !group vaultName/lobUser/ORACLE_CLOUD_DB/delegation/consumers
- !grant
  roles: !group vaultName/lobUser/ORACLE_CLOUD_DB/delegation/consumers
  member: !host app1

# granting 'app1' retrieve only privileges to safe 'COUCH_PREM_DB'
- !group vaultName/lobUser/COUCH_PREM_DB/delegation/consumers
- !grant
  roles: !group vaultName/lobUser/COUCH_PREM_DB/delegation/consumers
  member: !host app1
### --- end policy for app1 ---

.LINK
#>
Function Get-ConjurAppPolicy
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $AppName,
        [string]
        $VaultName = $env:CONJUR_VAULT_NAME,
        [string]
        $LobUser = $env:CONJUR_LOB_USER,
        [string[]]
        $AdminSafes = $(),
        [string[]]
        $ConsumerSafes = $(),
        [string]
        $Authenticator = "",
        [Switch]
        $CreateNamespace,
        [string]
        $ConjurTemplateFolder = ".\templates"
    )

    # validate mandatory parameters when safes are provided
    if ($AdminSafes.Count -ne 0 -or $ConsumerSafes.Count -ne 0)
    {
        if ([string]::IsNullOrEmpty($VaultName))
        {
            Throw "VaultName paramater is mandatory when using safes"
        }
        if ([string]::IsNullOrEmpty($LobUser))
        {
            Throw "LobUser paramater is mandatory when using safes"
        }
    }

    # conjur template files
    $appTemplate = "$ConjurTemplateFolder\app-template.yml"
    $authnTemplate = "$ConjurTemplateFolder\authn-template.yml"
    $namespaceTemplate = "$ConjurTemplateFolder\namespace-template.yml"
    $safeAdminTemplate = "$ConjurTemplateFolder\safe-admin-template.yml"
    $safeConsumerTemplate = "$ConjurTemplateFolder\safe-consumer-template.yml"

    # all of these values will be replaced within the policy
    $replaceDictionary = @{
        "<appName>" = $AppName
        "<authenticator>" = $Authenticator
        "<vaultName>" = $VaultName
        "<lobUser>" = $LobUser
    }

    Write-Verbose -Message "Replacement dictionary: $replaceDictionary"

    # init all of the policies
    $authnPolicy = ""
    $namespacePolicy = ""
    $adminSafesPolicy = ""
    $consumerSafesPolicy = ""

    # generate the app policy, this is mandatory
    $appPolicy = Replace-KeyValue -FilePath $appTemplate -ReplaceDictionary $replaceDictionary
    $appPolicy += "`n"

    # generate the authenticator policy if provided
    if (![string]::IsNullOrEmpty($Authenticator))
    {
        $authnPolicy = Replace-KeyValue -FilePath $authnTemplate -ReplaceDictionary $replaceDictionary
        $authnPolicy += "`n"
    }
    # generate the namespace policy if true
    if ($CreateNamespace)
    {
        $namespacePolicy = Replace-KeyValue -FilePath $namespaceTemplate -ReplaceDictionary $replaceDictionary
        $namespacePolicy += "`n"
    }
    # generate the admin safes policy if provided
    foreach ($safe in $AdminSafes) 
    {
        $replaceDictionary.Add("<safeName>", $safe)
        $adminSafePolicy = Replace-KeyValue -FilePath $safeAdminTemplate -ReplaceDictionary $replaceDictionary
        $adminSafesPolicy += $adminSafePolicy + "`n"
        $replaceDictionary.Remove("<safeName>")
    }
    # generate the consumers safes policy if provided
    foreach ($safe in $ConsumerSafes) 
    {
        $replaceDictionary.Add("<safeName>", $safe)
        $consumerSafePolicy = Replace-KeyValue -FilePath $safeConsumerTemplate -ReplaceDictionary $replaceDictionary
        $consumerSafesPolicy += $consumerSafePolicy + "`n"
        $replaceDictionary.Remove("<safeName>")
    }

    $fullPolicy = $appPolicy  + $authnPolicy + $namespacePolicy + $adminSafesPolicy + $consumerSafesPolicy
    $fullPolicy = $fullPolicy.TrimEnd("`n") + "### --- end policy for $AppName ---"
    Write-Output $fullPolicy
}


<#
.SYNOPSIS

Create a conjur application.

.DESCRIPTION

Create a Conjur application that has permissions to its needed safes.

.PARAMETER ConjurApplianceUrl
The conjur appliance url.

.PARAMETER ConjurAccount
The conjur organization account. Can be found by executing: Invoke-RestMethod "https://<conjur appliance url>/info"

.PARAMETER Credential
The credential being used when connecting to the conjur api.

.PARAMETER AppName
The name of the application being created.

.PARAMETER VaultName
The name of the vault configured within conjur.
Mandatory when adding this app to a safes.
example secret: vaultName/lobUser/safeName/cyberark-object-name/password

.PARAMETER LobUser
The name of the LOB user configured within conjur.
Mandatory when adding this app to a safes.
example secret: vaultName/lobUser/safeName/cyberark-object-name/password

.PARAMETER AdminSafes
The name of the Cyberark Safe this application will be the owner of in conjur.
When an app is admin of a safe it has the ability to create, update and retrieve variable secrets within conjur.

.PARAMETER ConsumerSafes
The name of the Cyberark Safe this application will have retrieve secret access too.
When an app is a consumer of a safe it only has the ability to list and retrieve variable secrets within conjur.

.PARAMETER Authenticator
The authenticator this application will have access too. 
An example would be 'authn-iam/test'. 
Remember that this authenticator must be enabled and configured on the conjur appliance. 
To check an authenticators status perform 'Invoke-RestMethod -Uri "https://<conjur appliance url>/info"'.

.PARAMETER CreateNamespace
If a namespace should be created for this application.
The namespace will have the same name as the application.
The application will have the ability to load conjur policy within this namespace, 
essentially allowing this application to create any conjur resource.

.PARAMETER DryRun
This will only perform Get-ConjurAppPolicy and return the results.
This can be used to view the policy before actually applying the 
policy to conjur, use this when debugging.

.PARAMETER ConjurTemplateFolder
The conjur template folder path.
This folder is expected to have the following files: 
app-template.yml, authn-template.yml, namespace-template.yml, 
safe-admin-template.yml and safe-consumer-template.yml

.INPUTS

None. You cannot pipe objects to New-ConjurApp.

.OUTPUTS

System.String. The content of the conjur policy generated for this application

.EXAMPLE


.LINK
#>
Function New-ConjurApp
{
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $ConjurApplianceUrl = $env:CONJUR_APPLIANCE_URL,
        [Parameter(Mandatory=$true)]
        [string]
        $ConjurAccount = $env:CONJUR_ACCOUNT,
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]
        $Credential = "",
        [Parameter(Mandatory=$true)]
        [string]
        $AppName,
        [string]
        $VaultName = $env:CONJUR_VAULT_NAME,
        [string]
        $LobUser = $env:CONJUR_LOB_USER,
        [string[]]
        $AdminSafes = $(),
        [string[]]
        $ConsumerSafes = $(),
        [string]
        $Authenticator = "",
        [Switch]
        $CreateNamespace,
        [string]
        $ConjurTemplateFolder = ".\templates",
        [Switch]
        $DryRun,
        [Switch]
        $IgnoreSsl
    )
    
    # generate the conjur application policy
    $policyContent = Get-ConjurAppPolicy -AppName $AppName -ConsumerSafes $ConsumerSafes -AdminSafes $AdminSafes -VaultName $VaultName -LobUser $LobUser -Authenticator $Authenticator -ConjurTemplateFolder $ConjurTemplateFolder
    if ($DryRun)
    {
        Write-Host $policyContent
        return 
    }

    # create temp folder and temp file
    New-Item -Path ".\tmp" -ItemType Directory -Force | Out-Null
    $epochTime = Get-EpochTime
    $policyFilePath = ".\tmp\$AppName-$epochTime.yml"
    $output = Set-Content -Path $policyFilePath -Value $policyContent -Force

    # log into conjur and load in the app policy
    return Append-ConjurPolicy -PolicyIdentifier "root" -PolicyFilePath $policyFilePath -ConjurApplianceUrl $ConjurApplianceUrl -ConjurAccount $ConjurAccount -ConjurUsername $Credential.Username -ConjurPassword $Credential.GetNetworkCredential().password
}
