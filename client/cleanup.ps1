$ErrorActionPreference = 'Continue'
$id = '{{.}}'
$base = Join-Path $env:ProgramData "Paw\$id"
foreach ($task in @("Paw-SSH-$id","Paw-Cleanup-$id")) {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
}
Get-CimInstance Win32_Process -Filter "Name='ssh.exe' OR Name='sshd.exe' OR Name='plink.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf(($base + '\'), [StringComparison]::OrdinalIgnoreCase) -ge 0 } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
$account = Get-LocalUser -Name "paw$id" -ErrorAction SilentlyContinue
if ($account -and $account.Description -eq "Paw rescue $id") {
    Remove-LocalUser -Name $account.Name
}
if (Test-Path -LiteralPath $base) {
    Remove-Item -LiteralPath $base -Recurse -Force
}
Write-Host 'Paw session cleaned up.' -ForegroundColor Green
