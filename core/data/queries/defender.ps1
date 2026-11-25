# Every Microsoft Defender XDR incident with its alerts, as Microsoft Graph answers, saved to incidents.json.
# Run it in PowerShell with the Microsoft Graph PowerShell SDK installed, then load incidents.json.
Connect-MgGraph -Scopes "SecurityIncident.Read.All" -NoWelcome
$link = 'https://graph.microsoft.com/v1.0/security/incidents?$expand=alerts'
$pages = @()
while ($link) {
    Invoke-MgGraphRequest -Method GET -Uri $link -OutputFilePath page.json
    $page = Get-Content page.json -Raw -Encoding utf8
    $pages += $page
    $link = ($page | ConvertFrom-Json).'@odata.nextLink'
}
Remove-Item page.json
"[" + ($pages -join ",") + "]" | Set-Content incidents.json -Encoding utf8
