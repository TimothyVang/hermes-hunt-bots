param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Title)
# Live view of every lab_browser action the bots take, read from the tool's own audit logs.
$Host.UI.RawUI.WindowTitle = $Title
$seen = @{}
# Start from now: only actions taken after this window opened are shown.
foreach ($f in Get-ChildItem -Path $Root -Filter audit.jsonl -Recurse -ErrorAction SilentlyContinue) { $seen[$f.FullName] = @(Get-Content -LiteralPath $f.FullName).Count }

function Fit-Buffer {
  try { $r = $Host.UI.RawUI; $w = $r.WindowSize.Width
        if ($r.BufferSize.Width -ne $w) { $r.BufferSize = New-Object Management.Automation.Host.Size($w, 5000) } } catch {}
}
$color = @{ 'framework-researcher' = 'Cyan'; 'framework-network-analyst' = 'Yellow' }
$who = @{ 'framework-researcher' = 'Threat Hunter  '; 'framework-network-analyst' = 'Network Analyst' }
Write-Host "Watching $Root\*\audit.jsonl" -ForegroundColor DarkGray
while ($true) {
  Fit-Buffer
  foreach ($f in Get-ChildItem -Path $Root -Filter audit.jsonl -Recurse -ErrorAction SilentlyContinue) {
    $lines = @(Get-Content -LiteralPath $f.FullName -Encoding UTF8 -ErrorAction SilentlyContinue)
    $n = [int]$seen[$f.FullName]
    for ($i = $n; $i -lt $lines.Count; $i++) {
      try { $e = $lines[$i] | ConvertFrom-Json } catch { continue }
      $what = @($e.action, $e.page) -ne $null -join ' '
      if ($e.ref)   { $what += " ref=$($e.ref)" }
      if ($e.text)  { $what += " type '$($e.text)'" }
      if ($e.query) { $what += " search '$($e.query)'" }
      if ($e.key)   { $what += " key=$($e.key)" }
      if ($e.submit) { $what += ' +Enter' }
      $res = if ($e.ok -eq $false -or $e.error) { "BLOCKED/ERR $($e.error)" } else { 'ok' }
      $t = ([datetime]$e.time).ToLocalTime().ToString('HH:mm:ss')
      $c = if ($color[$e.profile]) { $color[$e.profile] } else { 'White' }
      Write-Host ("{0} {1} {2} -> {3}" -f $t, $who[$e.profile].Trim(), $what, $res) -ForegroundColor $c
    }
    $seen[$f.FullName] = $lines.Count
  }
  Start-Sleep -Milliseconds 400
}
