#requires -Version 5.1
<#
.SYNOPSIS
    Gère ou liste les méthodes External MFA et Microsoft Authenticator des membres d'un groupe Microsoft Entra ID.
.DESCRIPTION
    Le script se connecte à Microsoft Graph, recherche un groupe et traite ses membres utilisateurs.

    Modes :
    - Par défaut : ajoute une méthode External MFA.
    - -Remove : supprime la méthode External MFA indiquée.
    - -List : liste les méthodes External MFA, sans modification.
    - -RemoveMicrosoftAuthenticatorMethods : supprime uniquement les méthodes Microsoft Authenticator.

    Les modes -List, -Remove et -RemoveMicrosoftAuthenticatorMethods sont exclusifs.
    En mode ajout ou -Remove, le nom de politique External MFA est demandé au clavier s'il n'est pas fourni.
.PARAMETER GroupDisplayName
    Nom d'affichage exact du groupe Microsoft Entra ID.
.PARAMETER ExternalMfaPolicyName
    Nom affiché de la politique External MFA. Obligatoire uniquement en mode ajout ou -Remove ; demandé interactivement s'il est absent.
.PARAMETER List
    Liste les utilisateurs du groupe et leurs méthodes External MFA, sans modification.
.PARAMETER Remove
    Supprime la méthode External MFA associée à la politique demandée.
.PARAMETER RemoveMicrosoftAuthenticatorMethods
    Supprime uniquement les méthodes Microsoft Authenticator des membres du groupe. Ce mode ne demande ni ne traite External MFA.
.PARAMETER IncludeNestedGroups
    Inclut les membres utilisateurs transitifs des groupes imbriqués.
.PARAMETER TenantId
    ID ou domaine facultatif du tenant Microsoft Entra ID.
.PARAMETER NoConfirm
    Désactive les confirmations interactives. L'alias -Force est accepté. -WhatIf reste prioritaire.
.PARAMETER StopOnError
    Arrête le script à la première erreur rencontrée.
.PARAMETER ExportCsvPath
    Chemin facultatif du rapport CSV.
.EXAMPLE
    .\Entra External MFA.ps1
    Demande le groupe puis la politique External MFA avant l'ajout.
.EXAMPLE
    .\Entra External MFA.ps1 -Remove
    Demande le groupe puis la politique External MFA avant la suppression.
.EXAMPLE
    .\Entra External MFA.ps1 -GroupDisplayName "TrustBuilder Users External MFA" -List
    Liste les utilisateurs et leurs méthodes External MFA.
.EXAMPLE
    .\Entra External MFA.ps1 -GroupDisplayName "TrustBuilder Users External MFA" -RemoveMicrosoftAuthenticatorMethods -WhatIf
    Simule uniquement la suppression des méthodes Microsoft Authenticator.
.NOTES
    Auteur       : Administrateur PowerShell
    Version      : 9.1.0
    Compatibilité: Windows PowerShell 5.1 et PowerShell 7+
    Modules      : Microsoft.Graph.Authentication, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns

    Disclaimer
    This sample is provided "AS IS" WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES of any kind
    You use this at your own risks
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$GroupDisplayName,
    [string]$ExternalMfaPolicyName,
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
$ErrorActionPreference = 'Stop'
$script:Results = New-Object System.Collections.Generic.List[object]
$modeCount = @($List, $Remove, $RemoveMicrosoftAuthenticatorMethods | Where-Object { $_ }).Count
if ($modeCount -gt 1) { throw 'Utilisez un seul mode parmi -List, -Remove ou -RemoveMicrosoftAuthenticatorMethods.' }

$policyRequired = -not $List -and -not $RemoveMicrosoftAuthenticatorMethods
if ($policyRequired -and [string]::IsNullOrWhiteSpace($ExternalMfaPolicyName)) {
    $operation = if ($Remove) { 'suppression External MFA' } else { 'ajout External MFA' }
    $ExternalMfaPolicyName = Read-Host -Prompt "Saisissez le nom exact de la politique External MFA pour le mode $operation"
    if ([string]::IsNullOrWhiteSpace($ExternalMfaPolicyName)) { throw "Le nom de la politique External MFA est obligatoire pour le mode $operation." }
}
if (($List -or $RemoveMicrosoftAuthenticatorMethods) -and -not [string]::IsNullOrWhiteSpace($ExternalMfaPolicyName)) {
    Write-Warning 'Le paramètre -ExternalMfaPolicyName est ignoré dans le mode actif.'
}

$script:Scopes = @('GroupMember.Read.All')
if ($List) { $script:Scopes += 'UserAuthMethod-External.Read' }
elseif ($Remove) { $script:Scopes += @('Policy.Read.All', 'UserAuthMethod-External.ReadWrite') }
elseif ($RemoveMicrosoftAuthenticatorMethods) { $script:Scopes += @('UserAuthenticationMethod.Read.All', 'UserAuthMethod-MicrosoftAuthApp.ReadWrite') }
else { $script:Scopes += @('Policy.Read.All', 'UserAuthMethod-External.ReadWrite') }
#endregion Initialisation et validation

#region Fonctions génériques
function Test-RequiredModule {
    [CmdletBinding()] param([Parameter(Mandatory = $true)][string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) { throw "Module absent : $Name. Installez-le avec Install-Module $Name -Scope CurrentUser" }
}
function Get-PropertyValue {
    [CmdletBinding()] param([object]$Object, [Parameter(Mandatory = $true)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
    if ($Object.PSObject.Properties.Name -contains 'AdditionalProperties' -and $Object.AdditionalProperties -and $Object.AdditionalProperties.ContainsKey($Name)) { return $Object.AdditionalProperties[$Name] }
    return $null
}
function Add-Result {
    [CmdletBinding()] param([object]$User, [string]$Action, [string]$Status, [string]$Detail, [string]$MethodId)
    $script:Results.Add([pscustomobject]@{ DateHeure=Get-Date -Format 'yyyy-MM-dd HH:mm:ss'; UserPrincipalName=$User.UserPrincipalName; UserDisplayName=$User.DisplayName; Action=$Action; Etat=$Status; MethodId=$MethodId; Detail=$Detail })
}
function Test-RunOperation {
    [CmdletBinding()] param([Parameter(Mandatory = $true)][string]$Target, [Parameter(Mandatory = $true)][string]$Action)
    if ($WhatIfPreference) { return $PSCmdlet.ShouldProcess($Target, $Action) }
    if ($NoConfirm) { return $true }
    return $PSCmdlet.ShouldProcess($Target, $Action)
}
#endregion Fonctions génériques

#region Fonctions Microsoft Graph
function Get-TargetGroup {
    [CmdletBinding()] param([Parameter(Mandatory = $true)][string]$DisplayName)
    $escaped = $DisplayName.Replace("'", "''")
    $groups = @(Get-MgGroup -Filter "displayName eq '$escaped'" -ConsistencyLevel eventual -All -Property 'id,displayName' -ErrorAction Stop)
    if ($groups.Count -eq 0) { throw "Aucun groupe ne porte exactement le nom '$DisplayName'." }
    if ($groups.Count -gt 1) { throw "Plusieurs groupes portent le nom '$DisplayName'. Utilisez un nom unique." }
    return $groups[0]
}
function Get-TargetUsers {
    [CmdletBinding()] param([Parameter(Mandatory = $true)][string]$GroupId)
    if ($IncludeNestedGroups) { return @(Get-MgGroupTransitiveMemberAsUser -GroupId $GroupId -All -Property 'id,displayName,userPrincipalName,accountEnabled' -ErrorAction Stop) }
    return @(Get-MgGroupMemberAsUser -GroupId $GroupId -All -Property 'id,displayName,userPrincipalName,accountEnabled' -ErrorAction Stop)
}
function Get-ExternalConfiguration {
    [CmdletBinding()] param([Parameter(Mandatory = $true)][string]$DisplayName)
    $policy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
    $configs = @($policy.AuthenticationMethodConfigurations | Where-Object { (Get-PropertyValue $_ '@odata.type') -eq '#microsoft.graph.externalAuthenticationMethodConfiguration' })
    $matches = @($configs | Where-Object { (Get-PropertyValue $_ 'displayName') -eq $DisplayName })
    if ($matches.Count -eq 0) { throw "Aucune politique External MFA ne porte le nom '$DisplayName'." }
    if ($matches.Count -gt 1) { throw "Plusieurs politiques External MFA portent le nom '$DisplayName'." }
    return $matches[0]
}
function Get-ExternalMethods {
    [CmdletBinding()] param([Parameter(Mandatory = $true)][string]$UserId)
    if (Get-Command Get-MgUserAuthenticationExternalAuthenticationMethod -ErrorAction SilentlyContinue) { return @(Get-MgUserAuthenticationExternalAuthenticationMethod -UserId $UserId -All -ErrorAction Stop) }
    if (Get-Command Get-MgBetaUserAuthenticationExternalAuthenticationMethod -ErrorAction SilentlyContinue) { return @(Get-MgBetaUserAuthenticationExternalAuthenticationMethod -UserId $UserId -All -ErrorAction Stop) }
    throw "Le cmdlet de lecture External MFA est introuvable."
}
function New-ExternalMethod {
    [CmdletBinding()] param([string]$UserId, [string]$ConfigurationId, [string]$DisplayName)
    $body = @{ '@odata.type'='#microsoft.graph.externalAuthenticationMethod'; configurationId=$ConfigurationId; displayName=$DisplayName }
    if (Get-Command New-MgUserAuthenticationExternalAuthenticationMethod -ErrorAction SilentlyContinue) { return New-MgUserAuthenticationExternalAuthenticationMethod -UserId $UserId -BodyParameter $body -ErrorAction Stop }
    if (Get-Command New-MgBetaUserAuthenticationExternalAuthenticationMethod -ErrorAction SilentlyContinue) { return New-MgBetaUserAuthenticationExternalAuthenticationMethod -UserId $UserId -BodyParameter $body -ErrorAction Stop }
    throw "Le cmdlet de création External MFA est introuvable."
}
function Remove-ExternalMethod {
    [CmdletBinding()] param([string]$UserId, [string]$MethodId)
    if (Get-Command Remove-MgUserAuthenticationExternalAuthenticationMethod -ErrorAction SilentlyContinue) { Remove-MgUserAuthenticationExternalAuthenticationMethod -UserId $UserId -ExternalAuthenticationMethodId $MethodId -Confirm:$false -ErrorAction Stop; return }
    if (Get-Command Remove-MgBetaUserAuthenticationExternalAuthenticationMethod -ErrorAction SilentlyContinue) { Remove-MgBetaUserAuthenticationExternalAuthenticationMethod -UserId $UserId -ExternalAuthenticationMethodId $MethodId -Confirm:$false -ErrorAction Stop; return }
    throw "Le cmdlet de suppression External MFA est introuvable."
}
function Get-AuthenticatorMethods {
    [CmdletBinding()] param([string]$UserId)
    return @(Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $UserId -All -ErrorAction Stop)
}
function Remove-AuthenticatorMethod {
    [CmdletBinding()] param([string]$UserId, [string]$MethodId)
    Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $UserId -MicrosoftAuthenticatorAuthenticationMethodId $MethodId -Confirm:$false -ErrorAction Stop
}
#endregion Fonctions Microsoft Graph

#region Prérequis et connexion
foreach ($module in 'Microsoft.Graph.Authentication','Microsoft.Graph.Groups','Microsoft.Graph.Identity.SignIns') { Test-RequiredModule $module; Import-Module $module -ErrorAction Stop }
$connect = @{ Scopes=$script:Scopes; NoWelcome=$true; ErrorAction='Stop' }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect
$group = Get-TargetGroup -DisplayName $GroupDisplayName
$users = @(Get-TargetUsers -GroupId $group.Id)
if ($users.Count -eq 0) { Write-Warning "Le groupe '$($group.DisplayName)' ne contient aucun utilisateur."; Disconnect-MgGraph; return }
#endregion Prérequis et connexion

#region Mode liste
if ($List) {
    $out = foreach ($user in $users) {
        try {
            $names = @(Get-ExternalMethods $user.Id | ForEach-Object { $n = Get-PropertyValue $_ 'displayName'; if ([string]::IsNullOrWhiteSpace($n)) { '<Nom non disponible>' } else { $n } })
            [pscustomobject]@{ Utilisateur=$user.UserPrincipalName; Nom=$user.DisplayName; ExternalMfa=if ($names.Count) { $names -join ' | ' } else { 'Aucune' } }
        } catch { [pscustomobject]@{ Utilisateur=$user.UserPrincipalName; Nom=$user.DisplayName; ExternalMfa="Erreur : $($_.Exception.Message)" } }
    }
    $out | Sort-Object Utilisateur | Format-Table -AutoSize Utilisateur,Nom,ExternalMfa
    if ($ExportCsvPath) { $out | Sort-Object Utilisateur | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ';' }
    Disconnect-MgGraph; return
}
#endregion Mode liste

#region Mode suppression Microsoft Authenticator
if ($RemoveMicrosoftAuthenticatorMethods) {
    foreach ($user in $users) {
        if ($user.AccountEnabled -eq $false) { Add-Result $user 'SuppressionAuthenticator' 'Ignoré' 'Compte désactivé.' $null; continue }
        try {
            $methods = @(Get-AuthenticatorMethods $user.Id)
            if ($methods.Count -eq 0) { Add-Result $user 'SuppressionAuthenticator' 'Absente' 'Aucune méthode Microsoft Authenticator.' $null; continue }
            foreach ($method in $methods) {
                if (-not $method.Id) { Add-Result $user 'SuppressionAuthenticator' 'Erreur' 'Méthode sans identifiant.' $null; continue }
                if (Test-RunOperation "$($user.DisplayName) <$($user.UserPrincipalName)>" "Supprimer Microsoft Authenticator [$($method.Id)]") {
                    Remove-AuthenticatorMethod $user.Id $method.Id
                    Add-Result $user 'SuppressionAuthenticator' 'Supprimé' 'Méthode Microsoft Authenticator supprimée.' $method.Id
                } else { Add-Result $user 'SuppressionAuthenticator' 'Simulé' 'Suppression non exécutée.' $method.Id }
            }
        } catch { Add-Result $user 'SuppressionAuthenticator' 'Erreur' $_.Exception.Message $null; if ($StopOnError) { throw } }
    }
} else {
#endregion Mode suppression Microsoft Authenticator

#region Modes ajout et suppression External MFA
    $configuration = Get-ExternalConfiguration -DisplayName $ExternalMfaPolicyName
    $configurationId = $configuration.Id
    $configurationName = Get-PropertyValue $configuration 'displayName'
    if (-not $configurationName) { $configurationName = $ExternalMfaPolicyName }
    foreach ($user in $users) {
        if ($user.AccountEnabled -eq $false) { Add-Result $user $(if($Remove){'SuppressionExternalMfa'}else{'AjoutExternalMfa'}) 'Ignoré' 'Compte désactivé.' $null; continue }
        try {
            $methods = @(Get-ExternalMethods $user.Id | Where-Object { (Get-PropertyValue $_ 'configurationId') -eq $configurationId })
            if ($Remove) {
                if ($methods.Count -eq 0) { Add-Result $user 'SuppressionExternalMfa' 'Absente' 'Aucune méthode External MFA correspondante.' $null; continue }
                foreach ($method in $methods) {
                    if (Test-RunOperation "$($user.DisplayName) <$($user.UserPrincipalName)>" "Supprimer External MFA '$configurationName' [$($method.Id)]") {
                        Remove-ExternalMethod $user.Id $method.Id
                        Add-Result $user 'SuppressionExternalMfa' 'Supprimé' "Méthode '$configurationName' supprimée." $method.Id
                    } else { Add-Result $user 'SuppressionExternalMfa' 'Simulé' 'Suppression non exécutée.' $method.Id }
                }
            } elseif ($methods.Count -gt 0) {
                Add-Result $user 'AjoutExternalMfa' 'DéjàPrésent' "Méthode '$configurationName' déjà configurée." $methods[0].Id
            } elseif (Test-RunOperation "$($user.DisplayName) <$($user.UserPrincipalName)>" "Ajouter External MFA '$configurationName'") {
                $created = New-ExternalMethod $user.Id $configurationId $configurationName
                Add-Result $user 'AjoutExternalMfa' 'Ajouté' "Méthode '$configurationName' ajoutée." $created.Id
            } else { Add-Result $user 'AjoutExternalMfa' 'Simulé' 'Création non exécutée.' $null }
        } catch { Add-Result $user $(if($Remove){'SuppressionExternalMfa'}else{'AjoutExternalMfa'}) 'Erreur' $_.Exception.Message $null; if ($StopOnError) { throw } }
    }
}
#endregion Modes ajout et suppression External MFA

#region Bilan, export et déconnexion
$script:Results | Group-Object Action,Etat | Sort-Object Name | ForEach-Object { Write-Host ('{0,-50} : {1}' -f $_.Name,$_.Count) }
$script:Results | Sort-Object UserPrincipalName,Action,Etat | Format-Table -AutoSize UserPrincipalName,UserDisplayName,Action,Etat,MethodId,Detail
if ($ExportCsvPath) { $script:Results | Sort-Object UserPrincipalName,Action,Etat | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ';' }
Disconnect-MgGraph -ErrorAction SilentlyContinue
#endregion Bilan, export et déconnexion

<#
.SYNOPSIS
    Gère les méthodes External MFA et Microsoft Authenticator pour les membres d'un groupe.
.DESCRIPTION
    En ajout ou avec -Remove, ExternalMfaPolicyName est demandé s'il n'est pas fourni.
    Avec -List, le script liste les méthodes External MFA sans modification.
    Avec -RemoveMicrosoftAuthenticatorMethods, il supprime seulement Microsoft Authenticator, sans demander de politique External MFA.
.EXAMPLE
    .\Entra External MFA.ps1 -GroupDisplayName "TrustBuilder Users External MFA" -List
.EXAMPLE
    .\Entra External MFA.ps1 -GroupDisplayName "TrustBuilder Users External MFA" -RemoveMicrosoftAuthenticatorMethods -WhatIf
.EXAMPLE
    .\Entra External MFA.ps1 -Remove
.NOTES
    Utilisez -WhatIf avant toute opération de suppression réelle.
#>
