# Manage Entra External MFA

Script PowerShell 5.1 et versions ultérieures utilisant Microsoft Graph pour gérer et inventorier les méthodes d'authentification des membres utilisateurs d'un groupe Microsoft Entra ID.

## Version 1.1.0 : changement des modes de liste

- `-ListExternalMFA` remplace l'ancien `-List` : affiche uniquement les méthodes External MFA enregistrées.
- `-List` affiche désormais toutes les méthodes d'authentification exposées par Graph, notamment External MFA, Microsoft Authenticator, mot de passe, téléphone, e-mail, FIDO2 / Passkey, OATH, Windows Hello for Business et les autres types renvoyés.
- Ces inventaires sont en lecture seule, ne demandent pas de politique External MFA et incluent aussi les comptes désactivés.
- Sortie minimale : utilisateur, nom et méthodes. Plusieurs méthodes sont séparées par ` | `.
- `Aucune` signifie que les lectures ont réussi sans méthode trouvée. Une erreur ou un résultat partiel est signalé explicitement.

La collection générale est complétée par la collection External MFA dédiée, sans doublons. L'inventaire se limite aux méthodes prises en charge et renvoyées par Graph : il ne vérifie ni leur utilisabilité ni la méthode par défaut et ne restitue aucun secret.

## Installation

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
```

Si les cmdlets External MFA stables sont absents, installez aussi :

```powershell
Install-Module Microsoft.Graph.Beta.Identity.SignIns -Scope CurrentUser
```

Le script établit une connexion administrateur interactive. Le consentement aux scopes ne remplace pas le rôle Entra requis pour les comptes ciblés, notamment Authentication Administrator ou Privileged Authentication Administrator selon leur niveau de privilège.

## Exemples

### External MFA uniquement

```powershell
& '.\Manage Entra External MFA.ps1' `
    -GroupDisplayName 'TrustBuilder Users External MFA' `
    -ListExternalMFA
```

### Toutes les méthodes d'authentification

```powershell
& '.\Manage Entra External MFA.ps1' `
    -GroupDisplayName 'TrustBuilder Users External MFA' `
    -List
```

### Membres transitifs et export CSV

```powershell
& '.\Manage Entra External MFA.ps1' `
    -GroupDisplayName 'TrustBuilder Users External MFA' `
    -List -IncludeNestedGroups -ExportCsvPath '.\Methodes.csv'
```

### Ajout External MFA

```powershell
& '.\Manage Entra External MFA.ps1' `
    -GroupDisplayName 'TrustBuilder Users External MFA' `
    -ExternalMfaPolicyName 'MFA externe - Fournisseur XYZ' `
    -WhatIf
```

### Suppression External MFA uniquement

```powershell
& '.\Manage Entra External MFA.ps1' `
    -GroupDisplayName 'TrustBuilder Users External MFA' `
    -ExternalMfaPolicyName 'MFA externe - Fournisseur XYZ' `
    -Remove -WhatIf
```

### Suppression autonome Microsoft Authenticator

```powershell
& '.\Manage Entra External MFA.ps1' `
    -GroupDisplayName 'TrustBuilder Users External MFA' `
    -RemoveMicrosoftAuthenticatorMethods -WhatIf
```

Retirez `-WhatIf` uniquement après validation. `-NoConfirm` (alias `-Force`) supprime les confirmations d'opérations, mais pas la connexion ou la demande des paramètres manquants. `-WhatIf` reste prioritaire pour les modifications de méthodes.

## Paramètres

| Paramètre | Rôle |
|---|---|
| `-GroupDisplayName` | Nom exact du groupe ; demandé si absent. |
| `-ExternalMfaPolicyName` | Configuration External MFA ; demandée en ajout ou avec `-Remove` si absente. |
| `-ListExternalMFA` | Liste External MFA uniquement. |
| `-List` | Liste toutes les méthodes exposées par Graph, External MFA inclus. |
| `-Remove` | Supprime uniquement l'External MFA ciblée. |
| `-RemoveMicrosoftAuthenticatorMethods` | Supprime uniquement Microsoft Authenticator sans consulter External MFA. |
| `-IncludeNestedGroups` | Inclut les utilisateurs membres transitifs. |
| `-TenantId` | Tenant de connexion facultatif. |
| `-NoConfirm` | Désactive les confirmations ; alias `-Force`. |
| `-StopOnError` | Arrête à la première erreur. |
| `-ExportCsvPath` | Rapport CSV UTF-8, séparateur point-virgule. |

Les options `-ListExternalMFA`, `-List`, `-Remove` et `-RemoveMicrosoftAuthenticatorMethods` sont exclusives. Sans option, le mode ajout External MFA est utilisé. Les noms de groupes ambigus sont refusés. Les objets non utilisateurs ne sont pas traités. Les modes de modification conservent l'exclusion des comptes désactivés.

## Autorisations déléguées

Tous les modes demandent `GroupMember.Read.All` et `User.Read.All` pour les groupes et les propriétés utilisateur affichées.

| Mode | Scopes supplémentaires |
|---|---|
| `-ListExternalMFA` | `UserAuthMethod-External.Read` |
| `-List` | `UserAuthenticationMethod.Read.All`, `UserAuthMethod-External.Read` |
| Ajout / `-Remove` | `Policy.Read.All`, `UserAuthMethod-External.ReadWrite` |
| Suppression Authenticator | `UserAuthenticationMethod.Read.All`, `UserAuthMethod-MicrosoftAuthApp.ReadWrite` |

Les groupes à appartenance masquée peuvent nécessiter des autorisations supplémentaires ; le script ne les demande pas automatiquement.

## Sécurité et limites

- Les suppressions peuvent empêcher les utilisateurs de se connecter. Vérifiez leurs solutions de récupération avant toute suppression.
- Le script ne change ni les cibles de la politique globale ni la méthode d'authentification par défaut.
- Les inventaires ne lisent pas les méthodes Microsoft Authenticator via leur collection dédiée : le mode `-List` utilise la collection générale pour les méthodes non externes.
- Les sorties d'inventaire incluent les méthodes générales déjà obtenues même si la lecture External MFA échoue, et signalent alors l'erreur.
- L'export CSV est une écriture locale facultative, distincte de la simulation des modifications de méthodes avec `-WhatIf`.
- Cette version n'a pas été exécutée sur votre tenant ni validée par un interpréteur PowerShell dans l'environnement de génération. Testez les inventaires et les simulations avant toute modification réelle.

## Disclaimer

This sample is provided "AS IS" WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES of any kind
You use this at your own risks
