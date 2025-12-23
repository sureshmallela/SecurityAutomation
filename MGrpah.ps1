# Purpose:
#   Connects to Microsoft Graph, reads a list of login names from a CSV (single column, no header),
#   searches for any Azure AD/Entra users whose userPrincipalName starts with each login (i.e. login@*),
#   and outputs a CSV showing whether matches exist and the matched userPrincipalName(s).
#
# Usage / Notes:
#   - Requires Microsoft Graph PowerShell SDK (e.g., Install-Module Microsoft.Graph).
#   - The script calls Connect-MgGraph with "User.Read.All" scope; ensure the account has that consent.
#   - Input CSV: single column of logins, no header (this script sets header "LoginName").
#   - Output CSV path can be changed; current output: EntraUserLookup_ByPrefix_new1.csv.
#   - Finds all users where userPrincipalName starts with "login@"; multiple matches per login are listed.
#   - If no matches, records Exists = "No".
#   - Adjust or expand filters if you need different match logic (exact match, equals, mail, etc.).
#
# Security:
#   - Run in a secure environment; avoid leaving tokens or credentials exposed.
#   - Consider running with least-privilege scope required.

# ...existing code...
Connect-MgGraph -Scopes "User.Read.All"

# Import usernames (single column, no header)
$users = Import-Csv "c:\Scripts\UsersList.csv" -Header "LoginName"

$results = foreach ($row in $users) {

    $login = $row.LoginName.Trim()
    if ([string]::IsNullOrWhiteSpace($login)) { continue }

    # Look for any userPrincipalName that starts with "login@"
    $filter = "startsWith(userPrincipalName,'$login@')"
    $matchedUsers = Get-MgUser -Filter $filter

    if ($matchedUsers) {
        foreach ($user in $matchedUsers) {
            [pscustomobject]@{
                LoginName    = $login
                UserPrincipalName = $user.UserPrincipalName
                DisplayName  = $user.DisplayName
                Exists       = "Yes"
            }
        }
    }
    else {
        [pscustomobject]@{
            LoginName    = $login
            UserPrincipalName = "-"
            DisplayName  = "-"
            Exists       = "No"
        }
    }
}

$results | Format-Table
$results | Export-Csv "C:\Scripts\EntraUserLookup_ByPrefix_new1.csv" -NoTypeInformation
# ...existing code...
