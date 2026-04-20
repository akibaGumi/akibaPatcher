# akibaPatcher v1 - automatic 1.0.5 unlocker
# just in case, it drops debug log to desktop automatically
$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = "Akiba Patcher v1"

# setup rough logger
$logPath = "$env:USERPROFILE\Desktop\akiba_debug.log"
if (Test-Path $logPath) { rm $logPath -Force }
function log([string]$msg, [string]$color="White") {
    "[$((Get-Date).ToString('HH:mm:ss'))] $msg" | Out-File $logPath -Append
    Write-Host $msg -ForegroundColor $color
}

# uac check
$wid = [Security.Principal.WindowsIdentity]::GetCurrent()
$prp = New-Object Security.Principal.WindowsPrincipal($wid)
if (!$prp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    log "[-] Elevating to admin..." "Yellow"
    Start-Process powershell.exe -Arg "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

log "=== Akiba Patcher v1 ===" "Cyan"
$url = "https://archive.org/download/sof_1.0.5/csaudiointcsof-1.0.5.zip"
$expected = "70C440F0EF3712D1D00ABCAE7815F2281676A7DD80DAD3A3AD6F82044CE5326D"
$tmp = "$env:TEMP\akiba_$(Get-Random)"
mkdir $tmp | Out-Null

# 7z check
$7z = @("C:\Program Files\7-Zip\7z.exe", "C:\Program Files (x86)\7-Zip\7z.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (!$7z) { log "[-] 7-Zip missing. please install it." "Red"; exit }

# download & extract base
log "[*] Grabbing payload from archive.org..." "Cyan"
Invoke-WebRequest $url -OutFile "$tmp\drv.zip" -UseBasicParsing
Expand-Archive "$tmp\drv.zip" -Dest "$tmp\zip" -Force

$exe = Get-ChildItem "$tmp\zip" -Filter "*csaudio*.exe" -Recurse | Select-Object -First 1
if ((Get-FileHash $exe.FullName -Alg SHA256).Hash -ne $expected) {
    log "[-] Hash mismatch. aborting." "Red"; exit
}

# extract nsis payload & flatten for makecat
log "[*] Flattening nsis payload..." "Cyan"
& $7z x $exe.FullName "-o$tmp\nsis" -y *>&1 | Out-Null
$flat = "$tmp\flat"
mkdir $flat | Out-Null
Get-ChildItem "$tmp\nsis" -File -Recurse | Copy-Item -Dest $flat -Force

$sys = "$flat\csaudiointcsof.sys"
$inf = Get-ChildItem $flat -Filter "*.inf" | Where-Object { $_.Name -match "csaudiointcsof" -or (Get-Content $_.FullName -Raw) -match "csaudiointcsof" } | Select-Object -First 1
if (!(Test-Path $sys) -or !$inf) { log "[-] missing sys/inf." "Red"; exit }

# strip PE cert so windows doesnt complain about broken sigs
log "[*] Stripping authenticode header..." "Cyan"
$b = [IO.File]::ReadAllBytes($sys)
$pe = [BitConverter]::ToInt32($b, 0x3C)
$magic = [BitConverter]::ToUInt16($b, $pe + 24)
$sec = $pe + 24 + $(if ($magic -eq 0x20B) { 112 } else { 96 }) + 32
$cOff = [BitConverter]::ToInt32($b, $sec)
$cSize = [BitConverter]::ToInt32($b, $sec + 4)

if ($cOff -gt 0 -and $cSize -gt 0) {
    [Array]::Clear($b, $sec, 8)
    $b = $b[0..($cOff - 1)]
    log "[+] Cert bye bye ($cSize bytes)" "Green"
}

# hardcoded patches (1.0.5)
log "[*] Patching..." "Cyan"
$patches = @{
    0x0148 = @(0x15, 0x38)
    0x29E8 = @(0xEB)
    0x3254 = @(0x31, 0xC0, 0xC3)
    0x61A0 = @(0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3)
}

$count = 0
foreach ($k in $patches.Keys) {
    for ($i=0; $i -lt $patches[$k].Length; $i++) {
        if ($b[$k+$i] -ne $patches[$k][$i]) {
            $b[$k+$i] = $patches[$k][$i]; $count++
        }
    }
}
[IO.File]::WriteAllBytes($sys, $b)
log "[+] Patched $count bytes" "Green"

# bump inf date so windows prefers it
log "[*] Rebuilding catalog & bumping INF date..." "Cyan"
$d = (Get-Date).ToString("MM/dd/yyyy,yy.MM.dd.HHmm")
$infTxt = Get-Content $inf.FullName
$infTxt = $infTxt -replace "(?i)^DriverVer=.*", "DriverVer=$d"
Set-Content $inf.FullName $infTxt

# build .cdf
$cdf = "$flat\csaudiointcsof.cdf"
$cdfData = "[CatalogHeader]`nName=csaudiointcsof.cat`nPublicVersion=0x0000001`nEncodingType=0x00010001`nCATATTR1=0x10010001:OSAttr:2:10.0`n`n[CatalogFiles]"
Get-ChildItem $flat -File | Where-Object { $_.Extension -notmatch "\.(cat|cdf|exe)$" } | ForEach-Object { $cdfData += "`n<hash>$($_.Name)=$($_.Name)" }
Set-Content $cdf $cdfData

# makecat execution with github fallback
$mc = Get-Command "makecat.exe" -ea Ignore
$mcExe = if ($mc) { $mc.Source } else { "$tmp\makecat.exe" }

if (!$mc) {
    log "[*] makecat missing, pulling from github..." "Cyan"
    Invoke-WebRequest "https://raw.githubusercontent.com/akibaGumi/akibaPatcher/refs/heads/main/makecat.exe" -OutFile $mcExe -UseBasicParsing
}

if (Test-Path $mcExe) {
    pushd $flat
    & $mcExe -v $cdf *>&1 | Out-Null
    popd
} else {
    log "[-] makecat failed to download, pnp might reject this" "Yellow"
}

# enable test mode
if ((bcdedit /enum) -notmatch "testsigning\s+Yes") {
    log "[!] Test mode off. enabling..." "Yellow"
    bcdedit /set TESTSIGNING ON | Out-Null
}

# forge 20-year cert
log "[*] Forging root cert & signing..." "Cyan"
Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like '*Akiba Audio*' } | Remove-Item -Force -ea Ignore
$cert = New-SelfSignedCertificate -Subject "CN=Akiba Audio Corporation" -Type CodeSigningCert -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(20) -KeySpec Signature -KeyUsage DigitalSignature -KeyLength 2048 -HashAlgorithm SHA256

@('Root', 'TrustedPublisher') | ForEach-Object {
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store($_, 'LocalMachine')
    $s.Open('ReadWrite'); $s.Add($cert); $s.Close()
}

$toSign = @($sys)
if (Test-Path "$flat\csaudiointcsof.cat") { $toSign += "$flat\csaudiointcsof.cat" }
foreach ($f in $toSign) {
    Set-AuthenticodeSignature -FilePath $f -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com" *>&1 | Out-Null
}

# install the unpatched base stuff first
log "[*] Running base installer..." "Cyan"
Start-Process $exe.FullName -Arg "/S" -Wait -NoNewWindow

# nuke the official WHQL driver so ours takes priority
log "[*] Purging WHQL drivers from store..." "Cyan"
$drvs = pnputil /enum-drivers
$oem = ""
foreach ($l in ($drvs -split "`r`n")) {
    if ($l -match "Published Name:\s+(oem\d+\.inf)") { $oem = $matches[1] }
    if ($l -match "Original Name:\s+.*csaudiointcsof.*\.inf" -and $oem) {
        pnputil /delete-driver $oem /uninstall /force *>&1 | Out-Null
    }
}

# final injection
log "[*] Injecting patched driver..." "Cyan"
pnputil /add-driver $inf.FullName /install *>&1 | Out-Null
pnputil /scan-devices *>&1 | Out-Null

# cleanup
log "[*] cleaning up tmp files..." "Cyan"
Remove-Item $tmp -Recurse -Force -ea Ignore

log "[+] Akiba Patcher done. reboot your pc." "Green"
Read-Host "press enter to exit"
