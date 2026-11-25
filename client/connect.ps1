$ErrorActionPreference = 'Stop'
$identityUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identityUser)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open a 64-bit PowerShell window as administrator and paste the command again.'
}
if (![Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw 'Paw currently requires x64 Windows and 64-bit PowerShell.'
}
$cfg = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{{.}}')) | ConvertFrom-Json
$id = $cfg.id
$until = ([DateTimeOffset]$cfg.until).LocalDateTime
if ($until -le (Get-Date)) { throw 'The rescue window has expired.' }
$base = Join-Path $env:ProgramFiles "Paw\Sessions\$id"
$task = "Paw-SSH-$id"
$cleanupTask = "Paw-Cleanup-$id"
$account = "paw$id"
$cache = Join-Path $env:ProgramFiles 'CodexSupport\OpenSSH'
$log = Join-Path $env:TEMP "Paw-$id.log"

function Stage([string]$message) {
    Write-Host $message
    Add-Content -LiteralPath $log -Value "$(Get-Date -Format HH:mm:ss) $message" -ErrorAction SilentlyContinue
}
function Secure-Directory([string]$path) {
    & icacls.exe $path /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the Paw session directory.' }
}
function Download-Verified([string]$name, [string]$hash, [string]$path) {
    Invoke-WebRequest -UseBasicParsing -Uri "$($cfg.endpoint)/asset/$name" -OutFile $path -TimeoutSec 45
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash -ne $hash) {
        throw "$name checksum mismatch."
    }
}
function Free-LocalPort {
    $probe = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $probe.Start()
        return $probe.LocalEndpoint.Port
    } finally { $probe.Stop() }
}
function Test-Listening([int]$port) {
    $connection = [Net.Sockets.TcpClient]::new()
    try {
        $connection.Connect('127.0.0.1', $port)
        return $true
    } catch { return $false }
    finally { $connection.Dispose() }
}
function Get-ArchiveThroughProxy([string]$destination) {
    $proxy = $cfg.proxy
    $plink = Join-Path $cache "plink-$($cfg.plinkHash).exe"
    if (!(Test-Path -LiteralPath $plink) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $plink).Hash -ne $cfg.plinkHash) {
        Stage 'Downloading the SSH proxy helper...'
        Download-Verified 'plink.exe' $cfg.plinkHash "$plink.part"
        Move-Item -LiteralPath "$plink.part" -Destination $plink -Force
    }
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (!$curl) { throw 'The configured SSH download proxy requires Windows curl.exe.' }
    $proxyPort = 1080
    if (Test-Listening $proxyPort) { $proxyPort = Free-LocalPort }
    $secret = Join-Path $base 'proxy-password'
    $logFile = Join-Path $base 'proxy.log'
    $plinkArguments = '-ssh -batch -noagent -N -T -D 127.0.0.1:' + $proxyPort +
        ' -hostkey "' + $proxy.hostKey + '" -l ' + $proxy.user + ' -P ' + $proxy.port
    if ($proxy.password) {
        [IO.File]::WriteAllText($secret, [string]$proxy.password, [Text.UTF8Encoding]::new($false))
        $plinkArguments += ' -pwfile "' + $secret + '"'
    }
    $process = $null
    try {
        Stage "Opening the configured SSH download proxy at $($proxy.host)..."
        $process = Start-Process -FilePath $plink -ArgumentList ($plinkArguments + ' ' + $proxy.host) -NoNewWindow -RedirectStandardError $logFile -PassThru
        $ready = $false
        for ($i = 0; $i -lt 40; $i++) {
            if ($process.HasExited) {
                throw ('SSH download proxy failed. ' + (Get-Content -LiteralPath $logFile -Raw -ErrorAction SilentlyContinue))
            }
            if (Test-Listening $proxyPort) { $ready = $true; break }
            Start-Sleep -Milliseconds 250
        }
        if (!$ready) { throw 'The configured SSH download proxy did not start.' }
        Stage 'Downloading OpenSSH through the SSH proxy...'
        & $curl.Source --fail --location --connect-timeout 20 --max-time 120 --socks5-hostname "127.0.0.1:$proxyPort" --output $destination "$($cfg.endpoint)/asset/OpenSSH-Win64.zip"
        if ($LASTEXITCODE -ne 0) { throw 'OpenSSH download through the configured proxy failed.' }
    } finally {
        if ($process -and !$process.HasExited) { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $secret -Force -ErrorAction SilentlyContinue
    }
}
function Open-SSHCache {
    $required = @('ssh.exe','sshd.exe','ssh-keygen.exe','sshd-session.exe','sshd-auth.exe','ssh-shellhost.exe','libcrypto.dll')
    $priorCache = Join-Path $env:ProgramFiles 'Paw\Cache'
    $version = Join-Path $cache $cfg.archiveHash
    foreach ($root in @($cache, $priorCache)) {
        $bin = Join-Path (Join-Path $root $cfg.archiveHash) 'OpenSSH-Win64'
        $missing = $required | Where-Object { !(Test-Path -LiteralPath (Join-Path $bin $_) -PathType Leaf) }
        if (!$missing) { Stage ('Using cached OpenSSH at ' + $bin); return $bin }
    }
    $bin = Join-Path $version 'OpenSSH-Win64'
    New-Item -ItemType Directory -Path $version -Force | Out-Null
    $archive = Join-Path $version 'openssh.zip'
    $partial = "$archive.part"
    $staging = Join-Path $version 'extracting'
    try {
        if (!(Test-Path -LiteralPath $archive) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash -ne $cfg.archiveHash) {
            $oldArchive = Join-Path (Join-Path $priorCache $cfg.archiveHash) 'openssh.zip'
            if ((Test-Path -LiteralPath $oldArchive -PathType Leaf) -and
                (Get-FileHash -Algorithm SHA256 -LiteralPath $oldArchive).Hash -eq $cfg.archiveHash) {
                Stage 'Reusing the existing OpenSSH archive.'
                Copy-Item -LiteralPath $oldArchive -Destination $partial
            } elseif ($cfg.proxy.host) { Get-ArchiveThroughProxy $partial }
            else {
                Stage 'Downloading OpenSSH over HTTPS...'
                Download-Verified 'OpenSSH-Win64.zip' $cfg.archiveHash $partial
            }
            if ((Get-FileHash -Algorithm SHA256 -LiteralPath $partial).Hash -ne $cfg.archiveHash) {
                throw 'OpenSSH checksum mismatch.'
            }
            Move-Item -LiteralPath $partial -Destination $archive -Force
        }
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
        Stage 'Extracting OpenSSH...'
        Expand-Archive -LiteralPath $archive -DestinationPath $staging
        $built = Join-Path $staging 'OpenSSH-Win64'
        foreach ($name in $required) {
            if (!(Test-Path -LiteralPath (Join-Path $built $name) -PathType Leaf)) {
                throw "OpenSSH archive is missing $name."
            }
        }
        if (Test-Path -LiteralPath $bin) { Remove-Item -LiteralPath $bin -Recurse -Force }
        Move-Item -LiteralPath $built -Destination $bin
        return $bin
    } finally {
        Remove-Item -LiteralPath $partial,$staging -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$lock = [Threading.Mutex]::new($false, 'Global\Paw-rescue')
$locked = $false
$created = $false
$cleanupFile = Join-Path $base 'cleanup.ps1'
$tunnel = $null
function Run-Cleanup {
    & ([ScriptBlock]::Create([IO.File]::ReadAllText($cleanupFile)))
}
try {
    try { $locked = $lock.WaitOne(0) }
    catch [Threading.AbandonedMutexException] { $locked = $true }
    if (!$locked) { throw 'A Paw window is already running on this computer.' }
    if (Test-Path -LiteralPath $base) {
        if (Test-Path -LiteralPath $cleanupFile) { Run-Cleanup }
        if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force }
    }
    New-Item -ItemType Directory -Path $base -Force | Out-Null
    $created = $true
    Secure-Directory $base
    Stage "Paw rescue log: $log"
    Stage 'Preparing session cleanup...'
    Invoke-WebRequest -UseBasicParsing -Uri $cfg.cleanup -OutFile $cleanupFile -TimeoutSec 20
    $quotedCleanupPath = $cleanupFile.Replace("'", "''")
    $cleanupCommand = "& ([ScriptBlock]::Create([IO.File]::ReadAllText('$quotedCleanupPath')))"
    $encodedCleanup = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanupCommand))
    $cleanupAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -EncodedCommand $encodedCleanup"
    $fallback = New-ScheduledTaskTrigger -Once -At $until.AddMinutes(5)
    Register-ScheduledTask -TaskName $cleanupTask -Action $cleanupAction -Trigger $fallback -User SYSTEM -RunLevel Highest -Force | Out-Null

    $cacheLock = [Threading.Mutex]::new($false, 'Global\CodexSupport-OpenSSH-cache')
    $cacheLocked = $false
    try {
        try { $cacheLocked = $cacheLock.WaitOne([TimeSpan]::FromMinutes(3)) }
        catch [Threading.AbandonedMutexException] { $cacheLocked = $true }
        if (!$cacheLocked) { throw 'Timed out waiting for the OpenSSH cache.' }
        $bin = Open-SSHCache
    } finally {
        if ($cacheLocked) { $cacheLock.ReleaseMutex() }
        $cacheLock.Dispose()
    }
    Stage 'Generating the Windows SSH host key...'
    $hostKey = Join-Path $base 'host_ed25519'
    $keygenArguments = '-q -t ed25519 -f "' + $hostKey + '" -N ""'
    $keygen = Start-Process -FilePath (Join-Path $bin 'ssh-keygen.exe') -ArgumentList $keygenArguments -NoNewWindow -PassThru -Wait
    if ($keygen.ExitCode -ne 0 -or !(Test-Path -LiteralPath $hostKey)) { throw 'Unable to generate the Windows SSH host key.' }
    & icacls.exe $hostKey /setowner '*S-1-5-32-544' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not set the SSH host key owner.' }
    & icacls.exe $hostKey /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the SSH host key.' }

    $port = Free-LocalPort
    $sshdConfig = Join-Path $base 'sshd_config'
    $sshdSettings = @(
        "Port $port", 'ListenAddress 127.0.0.1', ('HostKey "' + $hostKey.Replace('\','/') + '"'),
        'PasswordAuthentication yes', 'PubkeyAuthentication no', 'KbdInteractiveAuthentication no',
        'AuthenticationMethods password', "AllowUsers $account", 'DisableForwarding yes',
        'Subsystem sftp internal-sftp', 'LogLevel VERBOSE'
    ) -join [Environment]::NewLine
    [IO.File]::WriteAllText($sshdConfig, $sshdSettings + [Environment]::NewLine, [Text.Encoding]::ASCII)
    $sshd = Join-Path $bin 'sshd.exe'
    & $sshd -t -f $sshdConfig
    if ($LASTEXITCODE -ne 0) { throw 'Windows SSH configuration failed validation.' }
    Stage 'Creating the temporary Windows SSH account...'
    $password = ConvertTo-SecureString $cfg.password -AsPlainText -Force
    try {
        New-LocalUser -Name $account -Password $password -Description "Paw rescue $id" -AccountExpires $until.AddMinutes(5) -UserMayNotChangePassword | Out-Null
    } finally { $password.Dispose() }
    Add-LocalGroupMember -SID 'S-1-5-32-544' -Member "$env:COMPUTERNAME\$account"
    $sshdArgs = '-D -f "' + $sshdConfig + '" -E "' + (Join-Path $base 'sshd.log') + '"'
    $sshdAction = New-ScheduledTaskAction -Execute $sshd -Argument $sshdArgs -WorkingDirectory $bin
    $sshdTaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $task -Action $sshdAction -Settings $sshdTaskSettings -User SYSTEM -RunLevel Highest -Force | Out-Null
    Start-ScheduledTask -TaskName $task
    Stage 'Starting local SSH...'
    $ready = $false
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Seconds 1
        $listeners = Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort $port -State Listen -ErrorAction SilentlyContinue
        foreach ($listener in $listeners) {
            $owner = Get-CimInstance Win32_Process -Filter ('ProcessId = {0}' -f $listener.OwningProcess)
            if ($owner -and $owner.Name -eq 'sshd.exe' -and $owner.CommandLine -and
                $owner.CommandLine.IndexOf($sshdConfig,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $ready = $true
                break
            }
        }
        if ($ready) { break }
    }
    if (!$ready) {
        $details = Get-Content -LiteralPath (Join-Path $base 'sshd.log') -Tail 20 -ErrorAction SilentlyContinue
        throw ("Windows SSH failed to start. " + ($details -join ' '))
    }
    Stage 'Registering the Windows SSH host key...'
    $payload = @{key = (Get-Content -LiteralPath "$hostKey.pub" -Raw).Trim()} | ConvertTo-Json -Compress
    Invoke-WebRequest -UseBasicParsing -Method POST -Uri "$($cfg.endpoint)/host-key" -ContentType 'application/json' -Body $payload -TimeoutSec 15 | Out-Null

    $identity = Join-Path $base 'relay-key'
    $known = Join-Path $base 'known_hosts'
    [IO.File]::WriteAllText($identity, [string]$cfg.relayKey, [Text.Encoding]::ASCII)
    & icacls.exe $identity /inheritance:r /grant:r ('*' + $identityUser.User.Value + ':F') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the relay identity.' }
    [IO.File]::WriteAllText($known, [string]$cfg.knownHost + [Environment]::NewLine, [Text.Encoding]::ASCII)
    $forward = "0.0.0.0:$($cfg.accessPort):127.0.0.1:$port"
    $sshArgs = '-NT -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes ' +
        '-o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 ' +
        '-o UserKnownHostsFile="' + $known + '" -i "' + $identity + '" -R ' + $forward + ' -p ' + $cfg.relayPort + ' paw@' + $cfg.relayHost
    Stage 'Connecting the rescue tunnel. Keep this window open, or press Ctrl+C to end it.'
    $tunnel = Start-Process -FilePath (Join-Path $bin 'ssh.exe') -ArgumentList $sshArgs -NoNewWindow -PassThru
    while (!$tunnel.WaitForExit(15000)) {
        try {
            $lease = Invoke-RestMethod -UseBasicParsing -Uri "$($cfg.endpoint)/lease" -TimeoutSec 5
            $next = ([DateTimeOffset]$lease.until).LocalDateTime
            if ($next -gt $until) {
                $fallback = New-ScheduledTaskTrigger -Once -At $next.AddMinutes(5)
                Set-ScheduledTask -TaskName $cleanupTask -Trigger $fallback | Out-Null
                Set-LocalUser -Name $account -AccountExpires $next.AddMinutes(5)
                $until = $next
                Stage "Window extended until $until."
            }
        } catch {
            if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 410) { break }
        }
    }
    if ($tunnel.HasExited -and $tunnel.ExitCode -ne 0 -and (Get-Date) -lt $until) {
        throw "The rescue tunnel disconnected with code $($tunnel.ExitCode)."
    }
} finally {
    if ($tunnel -and !$tunnel.HasExited) { Stop-Process -Id $tunnel.Id -Force -ErrorAction SilentlyContinue }
    try {
        if ($created) {
            if (Test-Path -LiteralPath $cleanupFile) { Run-Cleanup }
            elseif (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force }
        }
    } catch {
        Write-Warning ('Paw cleanup could not finish. Run the cleanup command from the web page. ' + $_.Exception.Message)
    } finally {
        if ($locked) { $lock.ReleaseMutex() }
        $lock.Dispose()
    }
}
