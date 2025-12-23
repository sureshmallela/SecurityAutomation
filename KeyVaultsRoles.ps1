
# Get all subscriptions you can access
$subs = Get-AzSubscription

$rows = @()

foreach ($s in $subs) {
  Write-Host "=== Subscription: $($s.Name) ($($s.Id)) ===" -ForegroundColor Cyan
  Set-AzContext -SubscriptionId $s.Id

  # List Key Vaults in this subscription
  $vaults = Get-AzResource -ResourceType "Microsoft.KeyVault/vaults"

  foreach ($v in $vaults) {
    $scope = $v.ResourceId
    Write-Host "-- Vault: $($v.Name) --" -ForegroundColor Yellow

    # Get assignments at the vault (including inherited from RG/sub)
    $assignments = Get-AzRoleAssignment -Scope $scope

    # Optionally filter to "Key Vault" roles only:
    # $assignments = $assignments | Where-Object { $_.RoleDefinitionName -like "*Key Vault*" }

    $rows += $assignments | Select-Object `
      @{n="Subscription";e={$s.Name}},
      @{n="Vault";e={$v.Name}},
      DisplayName, SignInName, RoleDefinitionName, Scope, ObjectType
  }
}

$rows | Export-Csv -Path ".\kv-rbac-assignments-all-subs.csv" -NoTypeInformation
