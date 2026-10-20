#requires -Version 5.1
<#
.SYNOPSIS
    Gère et liste les méthodes d'authentification des membres d'un groupe Entra ID.
.DESCRIPTION
    Ajoute External MFA par défaut. -Remove supprime External MFA ciblée.
    -ListExternalMFA remplace l'ancien -List : inventaire External MFA uniquement.
    -List inventorie toutes les méthodes exposées par Graph, complétées par la
    collection External MFA dédiée et fusionnées sans doublons.
    -RemoveMicrosoftAuthenticatorMethods supprime uniquement Microsoft Authenticator.
    Tous les modes explicites sont exclusifs. Les inventaires sont en lecture seule.
.PARAMETER GroupDisplayName
    Nom exact du groupe. PowerShell le demande s'il est absent.
.PARAMETER ExternalMfaPolicyName
    Nom exact de configuration External MFA, demandé si absent en ajout ou -Remove.
.PARAMETER ListExternalMFA
    Liste uniquement les méthodes External MFA des utilisateurs du groupe.
.PARAMETER List
    Liste toutes les méthodes d'authentification renvoyées par Microsoft Graph.
.PARAMETER Remove
    Supprime uniquement les méthodes liées à la configuration External MFA choisie.
.PARAMETER RemoveMicrosoftAuthenticatorMethods
    Supprime Microsoft Authenticator sans consulter ni modifier External MFA.
.PARAMETER IncludeNestedGroups
    Inclut les utilisateurs membres transitifs.
.PARAMETER TenantId
    ID ou domaine facultatif du tenant.
.PARAMETER NoConfirm
    Désactive les confirmations des opérations. Alias Force. -WhatIf reste prioritaire.
.PARAMETER StopOnError
    Arrête le traitement à la première erreur.
.PARAMETER ExportCsvPath
    Chemin facultatif du CSV UTF-8 séparé par des points-virgules.
.EXAMPLE
    & '.\Manage Entra External MFA.ps1' -GroupDisplayName 'TrustBuilder Users External MFA' -ListExternalMFA
.EXAMPLE
    & '.\Manage Entra External MFA.ps1' -GroupDisplayName 'TrustBuilder Users External MFA' -List
.NOTES
    Version : 1.1.0
    Compatibilité : Windows PowerShell 5.1 et PowerShell 7+.
    Disclaimer
    This sample is provided "AS IS" WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES of any kind
    You use this at your own risks
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$GroupDisplayName,
    [string]$ExternalMfaPolicyName,
    [switch]$ListExternalMFA,
    [switch]$List,
    [switch]$Remove,
    [switch]$RemoveMicrosoftAuthenticatorMethods,
    [switch]$IncludeNestedGroups,
    [string]$TenantId,
    [Alias('Force')][switch]$NoConfirm,
    [switch]$StopOnError,
    [string]$ExportCsvPath
)

#region Initialisation et validation
$ErrorActionPreference='Stop'
$operationCmdlet=$PSCmdlet
$results=New-Object System.Collections.Generic.List[object]
$modes=@(@($ListExternalMFA,$List,$Remove,$RemoveMicrosoftAuthenticatorMethods) | Where-Object { $_ })
if ($modes.Count -gt 1) {
    throw 'Choisissez un seul mode : -ListExternalMFA, -List, -Remove ou -RemoveMicrosoftAuthenticatorMethods.'
}
$isListing=$List -or $ListExternalMFA
if (-not $isListing -and -not $RemoveMicrosoftAuthenticatorMethods -and [string]::IsNullOrWhiteSpace($ExternalMfaPolicyName)) {
    $ExternalMfaPolicyName=Read-Host 'Nom exact de la politique External MFA'
    if ([string]::IsNullOrWhiteSpace($ExternalMfaPolicyName)) { throw 'Le nom de politique ne peut pas être vide.' }
}
$scopes=@('GroupMember.Read.All','User.Read.All')
if ($List) { $scopes+=@('UserAuthenticationMethod.Read.All','UserAuthMethod-External.Read') }
elseif ($ListExternalMFA) { $scopes+='UserAuthMethod-External.Read' }
elseif ($RemoveMicrosoftAuthenticatorMethods) { $scopes+=@('UserAuthenticationMethod.Read.All','UserAuthMethod-MicrosoftAuthApp.ReadWrite') }
else { $scopes+=@('Policy.Read.All','UserAuthMethod-External.ReadWrite') }
#endregion Initialisation et validation

#region Fonctions
function Get-PropertyValue([object]$Object,[string]$Name) {
    if ($null -eq $Object) { return $null }
    $property=$Object.PSObject.Properties[$Name]
    if ($null -ne $property -and $null -ne $property.Value) { return $property.Value }
    if ($Object.AdditionalProperties -and $Object.AdditionalProperties.ContainsKey($Name)) { return $Object.AdditionalProperties[$Name] }
    return $null
}
function Get-ExternalMethods([string]$UserId) {
    if (Get-Command Get-MgUserAuthenticationExternalAuthenticationMethod -ErrorAction SilentlyContinue) {
        return @(Get-MgUserAuthenticationExternalAuthenticationMethod -UserId $UserId -All -ErrorAction Stop)
    }
    if (Get-Command Get-MgBetaUserAuthenticationExternalAuthenticationMethod -ErrorAction SilentlyContinue) {
        return @(Get-MgBetaUserAuthenticationExternalAuthenticationMethod -UserId $UserId -All -ErrorAction Stop)
    }
    throw 'Cmdlet de lecture External MFA introuvable.'
}
function Get-MethodLabel([object]$Method) {
    $type=Get-PropertyValue $Method '@odata.type'
    $label=switch ($type) {
        '#microsoft.graph.externalAuthenticationMethod' { 'External MFA' }
        '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' { 'Microsoft Authenticator' }
        '#microsoft.graph.passwordAuthenticationMethod' { 'Mot de passe' }
        '#microsoft.graph.phoneAuthenticationMethod' { 'Téléphone' }
        '#microsoft.graph.emailAuthenticationMethod' { 'E-mail' }
        '#microsoft.graph.fido2AuthenticationMethod' { 'FIDO2 / Passkey' }
        '#microsoft.graph.softwareOathAuthenticationMethod' { 'Software OATH' }
        '#microsoft.graph.hardwareOathAuthenticationMethod' { 'Hardware OATH' }
        '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' { 'Windows Hello for Business' }
        '#microsoft.graph.temporaryAccessPassAuthenticationMethod' { 'Temporary Access Pass' }
        '#microsoft.graph.platformCredentialAuthenticationMethod' { 'Identifiant de plateforme' }
        default { if ($type) { $type -replace '^#microsoft\.graph\.','' } else { 'Type non identifié' } }
    }
    $name=Get-PropertyValue $Method 'displayName'
    if ($name) { return ('{0} : {1}' -f $label,$name) }
    return $label
}
function Add-Result([object]$User,[string]$Action,[string]$Etat,[string]$Detail,[string]$MethodId) {
    $results.Add([pscustomobject]@{
        Utilisateur=$User.UserPrincipalName;Nom=$User.DisplayName
        Action=$Action;Etat=$Etat;MethodId=$MethodId;Detail=$Detail
    })
}
function Test-RunOperation([string]$Target,[string]$Action) {
    if ($WhatIfPreference) { return $operationCmdlet.ShouldProcess($Target,$Action) }
    if ($NoConfirm) { return $true }
    return $operationCmdlet.ShouldProcess($Target,$Action)
}
#endregion Fonctions

#region Modules et connexion
foreach ($module in 'Microsoft.Graph.Authentication','Microsoft.Graph.Groups','Microsoft.Graph.Identity.SignIns') {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        throw "Module absent : $module. Installez-le avec Install-Module $module -Scope CurrentUser"
    }
    Import-Module $module -ErrorAction Stop
}
if (-not $RemoveMicrosoftAuthenticatorMethods -and -not (Get-Command Get-MgUserAuthenticationExternalAuthenticationMethod -ErrorAction SilentlyContinue)) {
    if (Get-Module -ListAvailable Microsoft.Graph.Beta.Identity.SignIns) {
        Import-Module Microsoft.Graph.Beta.Identity.SignIns -ErrorAction Stop
    }
}
$connect=@{Scopes=$scopes;NoWelcome=$true;ContextScope='Process';ErrorAction='Stop'}
if ($TenantId) { $connect.TenantId=$TenantId }
$connected=$false
try {
    Connect-MgGraph @connect | Out-Null
    $connected=$true
    $escaped=$GroupDisplayName.Replace("'","''")
    $groups=@(Get-MgGroup -Filter "displayName eq '$escaped'" -All -Property 'id,displayName' -ErrorAction Stop)
    if ($groups.Count -ne 1) { throw "Groupe introuvable ou ambigu : '$GroupDisplayName'." }
    if ($IncludeNestedGroups) {
        $users=@(Get-MgGroupTransitiveMemberAsUser -GroupId $groups[0].Id -All -Property 'id,displayName,userPrincipalName,accountEnabled' -ErrorAction Stop)
    } else {
        $users=@(Get-MgGroupMemberAsUser -GroupId $groups[0].Id -All -Property 'id,displayName,userPrincipalName,accountEnabled' -ErrorAction Stop)
    }
#endregion Modules et connexion

#region Modes liste
    if ($isListing) {
        foreach ($user in $users) {
            $labels=New-Object System.Collections.Generic.List[string]
            $seen=@{}
            $errors=New-Object System.Collections.Generic.List[string]
            if ($List) {
                try {
                    foreach ($method in @(Get-MgUserAuthenticationMethod -UserId $user.Id -All -ErrorAction Stop)) {
                        $type=Get-PropertyValue $method '@odata.type'
                        # External MFA est traité via sa collection dédiée ci-dessous.
                        if ($type -eq '#microsoft.graph.externalAuthenticationMethod') { continue }
                        $key='{0}:{1}' -f $type,$method.Id
                        if (-not $seen.ContainsKey($key)) {
                            $seen[$key]=$true
                            $labels.Add((Get-MethodLabel $method))
                        }
                    }
                } catch {
                    if ($StopOnError) { throw }
                    $errors.Add("Méthodes générales : $($_.Exception.Message)")
                }
            }
            try {
                foreach ($method in @(Get-ExternalMethods $user.Id)) {
                    $key='external:{0}' -f $method.Id
                    if (-not $seen.ContainsKey($key)) {
                        $seen[$key]=$true
                        $name=Get-PropertyValue $method 'displayName'
                        if (-not $name) { $name=Get-PropertyValue $method 'configurationId' }
                        $labels.Add(('External MFA : {0}' -f $name))
                    }
                }
            } catch {
                if ($StopOnError) { throw }
                $errors.Add("External MFA : $($_.Exception.Message)")
            }
            $text=if ($labels.Count) { $labels -join ' | ' } elseif ($errors.Count) { 'Lecture impossible' } else { 'Aucune' }
            if ($errors.Count) { $text+=' | Erreur : '+($errors -join ' | ') }
            $results.Add([pscustomobject]@{Utilisateur=$user.UserPrincipalName;Nom=$user.DisplayName;Methodes=$text})
        }
        $results | Sort-Object Utilisateur | Format-Table -AutoSize -Wrap Utilisateur,Nom,Methodes
    }
#endregion Modes liste

#region Modes de modification
    else {
        if (-not $RemoveMicrosoftAuthenticatorMethods) {
            $policy=Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
            $configs=@($policy.AuthenticationMethodConfigurations | Where-Object {
                (Get-PropertyValue $_ '@odata.type') -eq '#microsoft.graph.externalAuthenticationMethodConfiguration' -and
                (Get-PropertyValue $_ 'displayName') -eq $ExternalMfaPolicyName
            })
            if ($configs.Count -ne 1) { throw "Configuration External MFA introuvable ou ambiguë : '$ExternalMfaPolicyName'." }
            $configurationId=$configs[0].Id
        }
        foreach ($user in $users) {
            $action=if ($RemoveMicrosoftAuthenticatorMethods) { 'SuppressionAuthenticator' } elseif ($Remove) { 'SuppressionExternalMfa' } else { 'AjoutExternalMfa' }
            if ($user.AccountEnabled -eq $false) {
                Add-Result $user $action 'Ignoré' 'Compte désactivé.' $null
                continue
            }
            try {
                if ($RemoveMicrosoftAuthenticatorMethods) {
                    $methods=@(Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $user.Id -All -ErrorAction Stop)
                } else {
                    $methods=@(Get-ExternalMethods $user.Id | Where-Object { (Get-PropertyValue $_ 'configurationId') -eq $configurationId })
                }
                $target="$($user.DisplayName) <$($user.UserPrincipalName)>"
                if ($Remove -or $RemoveMicrosoftAuthenticatorMethods) {
                    if (-not $methods.Count) { Add-Result $user $action 'Absente' 'Aucune méthode correspondante.' $null }
                    foreach ($method in $methods) {
                        if (-not $method.Id) { throw 'Identifiant de méthode absent.' }
                        if (-not (Test-RunOperation $target "$action [$($method.Id)]")) {
                            Add-Result $user $action 'NonExécuté' 'Simulation ou confirmation refusée.' $method.Id
                            continue
                        }
                        if ($RemoveMicrosoftAuthenticatorMethods) {
                            Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $user.Id -MicrosoftAuthenticatorAuthenticationMethodId $method.Id -Confirm:$false -ErrorAction Stop
                        } else {
                            $cmd=Get-Command Remove-MgUserAuthenticationExternalAuthenticationMethod -ErrorAction SilentlyContinue
                            if (-not $cmd) { $cmd=Get-Command Remove-MgBetaUserAuthenticationExternalAuthenticationMethod -ErrorAction Stop }
                            & $cmd -UserId $user.Id -ExternalAuthenticationMethodId $method.Id -Confirm:$false -ErrorAction Stop
                        }
                        Add-Result $user $action 'Supprimé' 'Méthode supprimée.' $method.Id
                    }
                } elseif ($methods.Count) {
                    Add-Result $user $action 'DéjàPrésent' 'Méthode déjà configurée.' $methods[0].Id
                } elseif (Test-RunOperation $target "Ajouter External MFA '$ExternalMfaPolicyName'") {
                    $body=@{'@odata.type'='#microsoft.graph.externalAuthenticationMethod';configurationId=$configurationId;displayName=$ExternalMfaPolicyName}
                    $cmd=Get-Command New-MgUserAuthenticationExternalAuthenticationMethod -ErrorAction SilentlyContinue
                    if (-not $cmd) { $cmd=Get-Command New-MgBetaUserAuthenticationExternalAuthenticationMethod -ErrorAction Stop }
                    $created=& $cmd -UserId $user.Id -BodyParameter $body -ErrorAction Stop
                    Add-Result $user $action 'Ajouté' 'Méthode ajoutée.' $created.Id
                } else { Add-Result $user $action 'NonExécuté' 'Simulation ou confirmation refusée.' $null }
            } catch {
                Add-Result $user $action 'Erreur' $_.Exception.Message $null
                if ($StopOnError) { throw }
            }
        }
        $results | Sort-Object Utilisateur,Action | Format-Table -AutoSize -Wrap
    }
#endregion Modes de modification

#region Export et déconnexion
    if ($ExportCsvPath) {
        $directory=Split-Path -Path $ExportCsvPath -Parent
        if ($directory -and -not (Test-Path -LiteralPath $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
        $results | Sort-Object Utilisateur | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    }
} finally {
    if ($connected) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
}
#endregion Export et déconnexion

<#
.SYNOPSIS
    Gestion et inventaire des méthodes d'authentification des membres d'un groupe.
.DESCRIPTION
    -ListExternalMFA remplace l'ancien inventaire -List.
    -List liste toutes les méthodes exposées par Graph, External MFA inclus.
    Aucun inventaire ne demande de politique External MFA ni ne modifie le tenant.
.PARAMETER GroupDisplayName
    Nom exact du groupe Microsoft Entra ID.
.PARAMETER ExternalMfaPolicyName
    Nom de configuration demandé en ajout ou -Remove si absent.
.PARAMETER ListExternalMFA
    Inventaire External MFA uniquement.
.PARAMETER List
    Inventaire de toutes les méthodes exposées par Graph.
.PARAMETER Remove
    Suppression External MFA ciblée.
.PARAMETER RemoveMicrosoftAuthenticatorMethods
    Suppression autonome de Microsoft Authenticator.
.PARAMETER IncludeNestedGroups
    Inclut les utilisateurs membres transitifs.
.PARAMETER TenantId
    ID ou domaine du tenant.
.PARAMETER NoConfirm
    Désactive les confirmations d'opérations ; -WhatIf reste prioritaire.
.PARAMETER StopOnError
    Arrête le script à la première erreur.
.PARAMETER ExportCsvPath
    Chemin du rapport CSV.
.EXAMPLE
    & '.\Manage Entra External MFA.ps1' -GroupDisplayName 'TrustBuilder Users External MFA' -ListExternalMFA
.EXAMPLE
    & '.\Manage Entra External MFA.ps1' -GroupDisplayName 'TrustBuilder Users External MFA' -List -ExportCsvPath '.\Methodes.csv'
.NOTES
    Les erreurs de lecture sont signalées et jamais assimilées à une absence de méthode.
#>
