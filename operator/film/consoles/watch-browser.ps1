param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Title)
# Live view of every lab_browser action the bots take, read from the tool's own audit logs.
$Host.UI.RawUI.WindowTitle = $Title
. "$PSScriptRoot\font.ps1"
Set-ConsoleFont 20
$seen = @{}
# Start from now: only actions taken after this window opened are shown.
foreach ($f in Get-ChildItem -Path $Root -Filter audit.jsonl -Recurse -ErrorAction SilentlyContinue) { $seen[$f.FullName] = @(Get-Content -LiteralPath $f.FullName).Count }

function Fit-Buffer {
  try { $r = $Host.UI.RawUI; $w = $r.WindowSize.Width
        if ($r.BufferSize.Width -ne $w) { $r.BufferSize = New-Object Management.Automation.Host.Size($w, 5000) } } catch {}
}
$color = @{ 'framework-researcher' = 'Cyan'; 'framework-network-analyst' = 'Yellow' }
$who = @{ 'framework-researcher' = 'Hunter'; 'framework-network-analyst' = 'Analyst' }
$page = @{ 'kibana_discover' = 'discover'; 'lab_console' = 'console'; 'arkime_sessions' = 'sessions'; 'arkime_spiview' = 'spiview' }
Write-Host 'lab_browser - the bots driving their web tools' -ForegroundColor DarkGray
while ($true) {
  Fit-Buffer
  foreach ($f in Get-ChildItem -Path $Root -Filter audit.jsonl -Recurse -ErrorAction SilentlyContinue) {
    $lines = @(Get-Content -LiteralPath $f.FullName -Encoding UTF8 -ErrorAction SilentlyContinue)
    $n = [int]$seen[$f.FullName]
    for ($i = $n; $i -lt $lines.Count; $i++) {
      try { $e = $lines[$i] | ConvertFrom-Json } catch { continue }
      $what = @($e.action, $(if ($e.page) { $page[$e.page] })) -ne $null -join ' '
      if ($e.text)  { $what += " '$($e.text)'" }
      if ($e.query) { $what += " '$($e.query)'" }
      if ($e.key)   { $what += " $($e.key)" }
      if ($e.submit) { $what += ' +Enter' }
      $res = if ($e.ok -eq $false -or $e.error) { " ERR $($e.error)" } else { '' }
      $t = ([datetime]$e.time).ToLocalTime().ToString('HH:mm:ss')
      $c = if ($color[$e.profile]) { $color[$e.profile] } else { 'White' }
      Write-Host ("{0} {1} {2}{3}" -f $t, $who[$e.profile], $what, $res) -ForegroundColor $c
    }
    $seen[$f.FullName] = $lines.Count
  }
  Start-Sleep -Milliseconds 400
}
