# Manage Entra External MFA

Script PowerShell compatible Windows PowerShell 5.1 et PowerShell 7+ pour gérer les méthodes d’authentification External MFA et Microsoft Authenticator des membres d’un groupe Microsoft Entra ID, au moyen de Microsoft Graph.

## Fonctions

- Ajout d’une méthode External MFA aux membres d’un groupe.
- Suppression ciblée d’une méthode External MFA avec `-Remove`.
- Inventaire en lecture seule des méthodes External MFA avec `-List`.
- Suppression autonome des méthodes Microsoft Authenticator avec `-RemoveMicrosoftAuthenticatorMethods`.
- Prise en charge optionnelle des membres transitifs avec `-IncludeNestedGroups`.
- Simulation avec `-WhatIf`, confirmations interactives et désactivation contrôlée avec `-NoConfirm`.
- Export CSV facultatif avec `-ExportCsvPath`.

## Prérequis

Installez les modules PowerShell nécessaires :

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

Selon la disponibilité des cmdlets External MFA dans votre SDK Graph, le module suivant peut être requis :

```powershell
Install-Module Microsoft.Graph.Beta.Identity.SignIns -Scope CurrentUser
```

Le compte connecté doit avoir un rôle Microsoft Entra adapté, par exemple `Authentication Administrator`, `Privileged Authentication Administrator` ou `Global Administrator`.

## Utilisation

### Lister les méthodes External MFA

```powershell
.\Manage Entra External MFA.ps1 `
    -GroupDisplayName "TrustBuilder Users External MFA" `
    -List
```

### Ajouter une méthode External MFA

```powershell
.\Manage Entra External MFA.ps1 `
    -GroupDisplayName "TrustBuilder Users External MFA" `
    -ExternalMfaPolicyName "MFA externe - Fournisseur XYZ" `
    -WhatIf
```

Supprimez `-WhatIf` après validation de la simulation.

### Supprimer une méthode External MFA

```powershell
.\Manage Entra External MFA.ps1 `
    -GroupDisplayName "TrustBuilder Users External MFA" `
    -ExternalMfaPolicyName "MFA externe - Fournisseur XYZ" `
    -Remove `
    -WhatIf
```

### Supprimer Microsoft Authenticator uniquement

```powershell
.\Manage Entra External MFA.ps1 `
    -GroupDisplayName "TrustBuilder Users External MFA" `
    -RemoveMicrosoftAuthenticatorMethods `
    -WhatIf
```

### Exécution sans confirmation interactive

```powershell
.\Manage Entra External MFA.ps1 `
    -GroupDisplayName "TrustBuilder Users External MFA" `
    -RemoveMicrosoftAuthenticatorMethods `
    -NoConfirm `
    -ExportCsvPath ".\Suppression-MicrosoftAuthenticator.csv"
```

## Paramètres principaux

| Paramètre | Description |
|---|---|
| `-GroupDisplayName` | Nom exact du groupe Microsoft Entra ID. |
| `-ExternalMfaPolicyName` | Politique External MFA à ajouter ou supprimer. Demandée interactivement si absente en mode ajout ou `-Remove`. |
| `-List` | Liste les méthodes External MFA sans modification. |
| `-Remove` | Supprime la méthode External MFA ciblée. |
| `-RemoveMicrosoftAuthenticatorMethods` | Supprime uniquement les méthodes Microsoft Authenticator. |
| `-IncludeNestedGroups` | Inclut les membres utilisateurs transitifs. |
| `-NoConfirm` | Désactive les confirmations interactives. `-WhatIf` reste prioritaire. |
| `-ExportCsvPath` | Exporte le résultat dans un fichier CSV. |

## Sécurité

Commencez toujours par une exécution avec `-WhatIf`, notamment avant toute suppression de méthode d’authentification. Le mode `-RemoveMicrosoftAuthenticatorMethods` est autonome : il ne crée, ne consulte et ne supprime aucune méthode External MFA.

## Disclaimer

This sample is provided "AS IS" WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES of any kind.

You use this at your own risk.
