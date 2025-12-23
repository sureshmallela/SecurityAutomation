
<#
.SYNOPSIS
    Enumerate Key Vault role assignments (RBAC) across all subscriptions accessible to the current Azure login.

.DESCRIPTION
    This script iterates through all subscriptions returned by Get-AzSubscription, switches context into
    each subscription, finds Key Vault resources, and collects role assignments scoped to each vault.
    The collected data (Subscription, Vault, assignee DisplayName/SignInName, RoleDefinitionName, Scope, ObjectType)
    is exported to a CSV file for reporting or auditing purposes.

.NOTES
    - Useful for auditing who has access to Key Vaults across multiple subscriptions. ✅
    - Requires the Az PowerShell module and an account with permission to list subscriptions, resources, and role assignments.
    - The export file is written to .\kv-rbac-assignments-all-subs.csv by default.
    - You can uncomment the filter below to restrict results to roles whose names contain "Key Vault".
#>

# Get all subscriptions the current account can access. This returns subscription objects used to scope subsequent API calls.
$subs = Get-AzSubscription

# Container for collected role assignment rows to be exported later.
$rows = @()

foreach ($s in $subs) {
  # Informative output so the user knows which subscription is being processed.
  Write-Host "=== Subscription: $($s.Name) ($($s.Id)) ===" -ForegroundColor Cyan

  # Switch the Az context to the current subscription so resource queries target it.
  Set-AzContext -SubscriptionId $s.Id

  # List Key Vault resources in this subscription. We specifically query resource type Microsoft.KeyVault/vaults.
  $vaults = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults"

  foreach ($v in $vaults) {
    # The scope for role assignments is the resource ID of the Key Vault.
    $scope = $v.ResourceId
    Write-Host "-- Vault: $($v.Name) --" -ForegroundColor Yellow

    # Retrieve role assignments that apply at this vault's scope. This includes assignments applied directly to the vault.
    # Note: role assignments inherited from resource group or subscription-level may also appear depending on scope resolution.
    $assignments = Get-AzRoleAssignment -Scope $scope

    # Optionally filter to only roles related to Key Vault (uncomment if you want to limit the output):
    # $assignments = $assignments | Where-Object { $_.RoleDefinitionName -like "*Key Vault*" }

    # Add selected properties to the rows collection. We add Subscription and Vault to make the CSV self-contained.
    $rows += $assignments | Select-Object `
      @{n="Subscription";e={$s.Name}},
      @{n="Vault";e={$v.Name}},
      DisplayName, SignInName, RoleDefinitionName, Scope, ObjectType
  }
}

# Export the collected assignments to a CSV file for auditing, reporting, or further analysis.
$rows | Export-Csv -Path ".\kv-rbac-assignments-all-subs.csv" -NoTypeInformation

