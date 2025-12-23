
<# 
.SYNOPSIS
  Replace Azure AD principals for the same Key Vault RBAC roles using a CSV mapping.

.DESCRIPTION
  - Reads a CSV where each row maps OldPrincipal -> NewPrincipal.
  - For each (row, subscription, vault) it:
      * Finds RBAC assignments for OldPrincipal at Key Vault scopes
        (optionally including RG/Sub inherited).
      * Grants NewPrincipal the same RoleDefinitionId at the same scope.
      * Optionally removes OldPrincipal’s assignment after successful add.
  - Preserves custom roles by RoleDefinitionId.
  - Supports Users, Groups, Service Principals, Managed Identities (resolved to ObjectId).
  - Provides dry-run, pre-change snapshot, CSV/JSON logs.

.PARAMETERS
  -MappingCsv         : Path to CSV (required).
  -OutputPath         : Folder for logs (default: current directory).
  -IncludeInherited   : Global switch if per-row column is not present.
  -RemoveOld          : Remove old assignment after add.
  -ThrottleMs         : Sleep between operations to reduce throttling.
  -WhatIf             : Dry-run (simulate changes).
  -Confirm            : Prompt before applying changes.

.CSV Columns supported:
  Required: OldPrincipal, NewPrincipal
  Optional per-row: Subscription, VaultNamePattern, TagName, TagValue, IncludeInherited

.EXAMPLES
  # Dry-run for all mappings across all subscriptions
  .\Replace-KV-Roles-FromCsv.ps1 -MappingCsv .\principal-mapping.csv -WhatIf

  # Execute and remove old assignments after adding new
  .\Replace-KV-Roles-FromCsv.ps1 -MappingCsv .\principal-mapping.csv -RemoveOld

  # Global include of inherited RG/Sub roles, unless overridden per row
  .\Replace-KV-Roles-FromCsv.ps1 -MappingCsv .\principal-mapping.csv -IncludeInherited
#>

param(
  [Parameter(Mandatory=$true)]
  [string]$MappingCsv,

  [string]$OutputPath = ".",
  [int]$ThrottleMs = 0,

  [switch]$IncludeInherited,  # global default (per-row IncludeInherited overrides)
  [switch]$RemoveOld,
  [switch]$WhatIf,
  [switch]$Confirm
)

# --- Helper: Resolve identity to ObjectId (supports GUID, UPN/display, appId/display, group display) ---
function Resolve-PrincipalObjectId {
  param([string]$Identity)

  # Strict GUID format: 8-4-4-4-12 hex digits separated by hyphens
  if ($Identity -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $Identity } # Already GUID

  # Try User (UPN or display)
  $u = Get-AzADUser -Filter "userPrincipalName eq '$Identity'" -ErrorAction SilentlyContinue
  if (-not $u) { $u = Get-AzADUser -DisplayName $Identity -ErrorAction SilentlyContinue }
  if ($u) { return $u.Id }

  # Try Service Principal (appId or display)
  $sp = Get-AzADServicePrincipal -ApplicationId $Identity -ErrorAction SilentlyContinue
  if (-not $sp) { $sp = Get-AzADServicePrincipal -DisplayName $Identity -ErrorAction SilentlyContinue }
  if ($sp) { return $sp.Id }

  # Try Group (display)
  $g = Get-AzADGroup -DisplayName $Identity -ErrorAction SilentlyContinue
  if ($g) { return $g.Id }

  throw "Unable to resolve identity '$Identity' to an Azure AD ObjectId."
}

# --- Read and validate CSV ---
if (-not (Test-Path -Path $MappingCsv)) { throw "CSV file not found: $MappingCsv" }
$rows = Import-Csv -Path $MappingCsv
$rowCount = @($rows).Count  # Force array even for single row
if ($rowCount -eq 0) { throw "CSV has no rows." }
# Validate columns exist (check first row)
if (-not ($rows[0] | Get-Member -Name OldPrincipal -MemberType NoteProperty) -or 
    -not ($rows[0] | Get-Member -Name NewPrincipal -MemberType NoteProperty)) {
  throw "CSV must contain 'OldPrincipal' and 'NewPrincipal' columns."
}
# Ensure rows is always an array
if ($rowCount -eq 1) { $rows = @($rows) }

# --- Cache: subscription list and resolved ObjectIds to minimize repeated calls ---
try {
  $allSubs = @(Get-AzSubscription -ErrorAction Stop)
} catch {
  throw "Failed to retrieve subscriptions. Ensure you are logged in: Connect-AzAccount. Error: $($_.Exception.Message)"
}
if ($allSubs.Count -eq 0) { throw "No accessible subscriptions found." }
$principalCache = @{} # maps input string -> resolved ObjectId

function Get-ResolvedId {
  param([string]$idStr)
  if ($principalCache.ContainsKey($idStr)) { return $principalCache[$idStr] }
  $resolved = Resolve-PrincipalObjectId -Identity $idStr
  $principalCache[$idStr] = $resolved
  return $resolved
}

# --- Logging setup ---
$opsLog = New-Object System.Collections.ArrayList
$snapshotLog = New-Object System.Collections.ArrayList
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$csvPath = Join-Path $OutputPath "kv-rbac-replacement-$ts.csv"
$jsonPath = Join-Path $OutputPath "kv-rbac-replacement-$ts.json"
$snapshotCsv = Join-Path $OutputPath "kv-rbac-snapshot-old-$ts.csv"

# --- Process each mapping row ---
foreach ($row in $rows) {
  $oldPrincipalStr = [string]::IsNullOrWhiteSpace($row.OldPrincipal) ? $null : $row.OldPrincipal.Trim()
  $newPrincipalStr = [string]::IsNullOrWhiteSpace($row.NewPrincipal) ? $null : $row.NewPrincipal.Trim()
  
  if (-not $oldPrincipalStr -or -not $newPrincipalStr) {
    Write-Host "Skipping row: OldPrincipal and/or NewPrincipal are empty." -ForegroundColor Yellow
    continue
  }
  $rowSub = $row.PSObject.Properties.Match('Subscription') ? $row.Subscription : $null
  $rowVaultPattern = $row.PSObject.Properties.Match('VaultNamePattern') ? $row.VaultNamePattern : $null
  $rowTagName = $row.PSObject.Properties.Match('TagName') ? $row.TagName : $null
  $rowTagValue = $row.PSObject.Properties.Match('TagValue') ? $row.TagValue : $null
  $rowIncludeInherited = $row.PSObject.Properties.Match('IncludeInherited') ? ($row.IncludeInherited -in @('true', '1', 'yes', 'True')) : $IncludeInherited.IsPresent

  Write-Host "=== Mapping: '$oldPrincipalStr' -> '$newPrincipalStr' ===" -ForegroundColor Cyan

  # Resolve principals
  try {
    $oldObjectId = Get-ResolvedId -idStr $oldPrincipalStr
    $newObjectId = Get-ResolvedId -idStr $newPrincipalStr
  } catch {
    Write-Host "   Resolve error: $($_.Exception.Message). Skipping row." -ForegroundColor Red
    continue
  }

  # Determine subscriptions to process for this row
  $subsToProcess = @()
  if ($rowSub) {
    $match = @($allSubs | Where-Object { $_.Id -eq $rowSub -or $_.Name -eq $rowSub })
    if ($match.Count -eq 0) {
      Write-Host "   Subscription '$rowSub' not found or inaccessible. Skipping row." -ForegroundColor Yellow
      continue
    }
    $subsToProcess = $match
  } else {
    $subsToProcess = $allSubs
  }

  foreach ($s in $subsToProcess) {
    Write-Host "---- Subscription: $($s.Name) ($($s.Id)) ----" -ForegroundColor Yellow
    Set-AzContext -SubscriptionId $s.Id | Out-Null

    # Pull Key Vaults in this subscription
    $vaults = @(Get-AzResource -ResourceType "Microsoft.KeyVault/vaults" -ErrorAction SilentlyContinue)
    if ($vaults.Count -eq 0) {
      Write-Host "   No Key Vaults found in subscription. Skipping." -ForegroundColor DarkGray
      continue
    }

    # Apply optional filters
    if ($rowVaultPattern) {
      $vaults = $vaults | Where-Object { $_.Name -match $rowVaultPattern }
    }
    if ($rowTagName -and $rowTagValue) {
      $vaults = $vaults | Where-Object { $_.Tags.ContainsKey($rowTagName) -and $_.Tags[$rowTagName] -eq $rowTagValue }
    }

    foreach ($v in $vaults) {
      $scope = $v.ResourceId
      Write-Host "------ Vault: $($v.Name) ------" -ForegroundColor Green

      # Get assignments at or inherited to the vault scope
      $assignments = Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue

      # Snapshot: all old-principal assignments associated with this vault scope
      $oldAssignmentsAll = $assignments | Where-Object { $_.ObjectId -eq $oldObjectId }
      foreach ($snap in $oldAssignmentsAll) {
        [void]$snapshotLog.Add([pscustomobject]@{
          Timestamp      = (Get-Date)
          MappingOld     = $oldPrincipalStr
          MappingNew     = $newPrincipalStr
          Subscription   = $s.Name
          SubscriptionId = $s.Id
          Vault          = $v.Name
          Scope          = $snap.Scope
          RoleName       = $snap.RoleDefinitionName
          RoleId         = $snap.RoleDefinitionId
          OldObjectId    = $oldObjectId
        })
      }

      # Restrict to exact vault-level scope if IncludeInherited is false
      if (-not $rowIncludeInherited) {
        $assignments = $assignments | Where-Object { $_.Scope -eq $scope }
      }

      # Old principal assignments to replicate
      $oldAssignments = $assignments | Where-Object { $_.ObjectId -eq $oldObjectId }

      foreach ($a in $oldAssignments) {
        $roleName    = $a.RoleDefinitionName
        $roleDefId   = $a.RoleDefinitionId
        $targetScope = $a.Scope

        # Avoid duplicates
        $exists = Get-AzRoleAssignment -ObjectId $newObjectId -Scope $targetScope -ErrorAction SilentlyContinue |
                  Where-Object { $_.RoleDefinitionId -eq $roleDefId }
        if ($exists) {
          Write-Host "   Skip(Add): new already has '$roleName' at $targetScope" -ForegroundColor DarkGray
          [void]$opsLog.Add([pscustomobject]@{
            Timestamp      = (Get-Date)
            MappingOld     = $oldPrincipalStr
            MappingNew     = $newPrincipalStr
            Subscription   = $s.Name
            SubscriptionId = $s.Id
            Vault          = $v.Name
            Scope          = $targetScope
            Action         = "Skip(Add)"
            Role           = $roleName
            RoleId         = $roleDefId
            OldObjectId    = $oldObjectId
            NewObjectId    = $newObjectId
            Status         = "Exists"
            Message        = "New principal already assigned"
          })
          continue
        }

        # Add role to new principal
        try {
          if ($WhatIf) {
            Write-Host "   WhatIf: Would add '$roleName' at $targetScope to new principal"
          } else {
            if ($Confirm) {
              $resp = Read-Host "Add '$roleName' at $targetScope to new principal? [y/N]"
              if ($resp -notin @('y','Y','yes','YES')) { throw "User declined add." }
            }
            New-AzRoleAssignment -ObjectId $newObjectId -RoleDefinitionId $roleDefId -Scope $targetScope -ErrorAction Stop | Out-Null
            Write-Host "   Added: '$roleName' at $targetScope" -ForegroundColor Cyan
            if ($ThrottleMs -gt 0) { Start-Sleep -Milliseconds $ThrottleMs }
          }

          [void]$opsLog.Add([pscustomobject]@{
            Timestamp      = (Get-Date)
            MappingOld     = $oldPrincipalStr
            MappingNew     = $newPrincipalStr
            Subscription   = $s.Name
            SubscriptionId = $s.Id
            Vault          = $v.Name
            Scope          = $targetScope
            Action         = "Add"
            Role           = $roleName
            RoleId         = $roleDefId
            OldObjectId    = $oldObjectId
            NewObjectId    = $newObjectId
            Status         = $WhatIf ? "Simulated" : "Success"
            Message        = ""
          })

          # Optional: remove old principal assignment
          if ($RemoveOld) {
            if ($WhatIf) {
              Write-Host "   WhatIf: Would remove old principal '$roleName' at $targetScope"
            } else {
              if ($Confirm) {
                $resp = Read-Host "Remove old principal '$roleName' at $targetScope? [y/N]"
                if ($resp -notin @('y','Y','yes','YES')) { throw "User declined remove." }
              }
              Remove-AzRoleAssignment -ObjectId $oldObjectId -RoleDefinitionId $roleDefId -Scope $targetScope -ErrorAction Stop
              Write-Host "   Removed old: '$roleName' at $targetScope" -ForegroundColor Cyan
              if ($ThrottleMs -gt 0) { Start-Sleep -Milliseconds $ThrottleMs }
            }

            [void]$opsLog.Add([pscustomobject]@{
              Timestamp      = (Get-Date)
              MappingOld     = $oldPrincipalStr
              MappingNew     = $newPrincipalStr
              Subscription   = $s.Name
              SubscriptionId = $s.Id
              Vault          = $v.Name
              Scope          = $targetScope
              Action         = "RemoveOld"
              Role           = $roleName
              RoleId         = $roleDefId
              OldObjectId    = $oldObjectId
              NewObjectId    = $newObjectId
              Status         = $WhatIf ? "Simulated" : "Success"
              Message        = ""
            })
          }
        }
        catch {
          Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Red
          [void]$opsLog.Add([pscustomobject]@{
            Timestamp      = (Get-Date)
            MappingOld     = $oldPrincipalStr
            MappingNew     = $newPrincipalStr
            Subscription   = $s.Name
            SubscriptionId = $s.Id
            Vault          = $v.Name
            Scope          = $targetScope
            Action         = $RemoveOld ? "Add+Remove" : "Add"
            Role           = $roleName
            RoleId         = $roleDefId
            OldObjectId    = $oldObjectId
            NewObjectId    = $newObjectId
            Status         = "Error"
            Message        = $_.Exception.Message
          })
        }
      }
    }
  }
}

# --- Export logs ---
$opsLog | Export-Csv -Path $csvPath -NoTypeInformation
$opsLog | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding utf8
$snapshotLog | Export-Csv -Path $snapshotCsv -NoTypeInformation

Write-Host "Operation log: $csvPath"
Write-Host "Operation log (JSON): $jsonPath"
Write-Host "Pre-change snapshot: $snapshotCsv"
