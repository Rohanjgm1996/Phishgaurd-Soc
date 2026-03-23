/*
  PhishGuard SOC — Malicious Attachment YARA Rules
  Defensive detection rules for common malicious file patterns.
*/

rule SuspiciousMacroAutoExec {
    meta:
        description = "Office document with auto-exec macro patterns"
        author      = "PhishGuard SOC"
        severity    = "high"
        reference   = "MITRE T1566.001, T1059.005"

    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $auto3 = "Auto_Open" nocase
        $auto4 = "Workbook_Open" nocase
        $auto5 = "AutoExec" nocase
        $shell = "Shell" nocase
        $obj   = "CreateObject" nocase
        $wsh   = "WScript" nocase

    condition:
        1 of ($auto*) and 1 of ($shell, $obj, $wsh)
}


rule ObfuscatedVBAMacro {
    meta:
        description = "VBA macro with character encoding obfuscation"
        author      = "PhishGuard SOC"
        severity    = "high"
        reference   = "MITRE T1027"

    strings:
        $chr1 = /Chr\(\d+\)/ nocase
        $chr2 = /ChrW\(\d+\)/ nocase
        $cat1 = "\"&\""
        $cat2 = "\" & \""

    condition:
        (#chr1 + #chr2) > 5 and (#cat1 + #cat2) > 3
}


rule MaliciousLNKFile {
    meta:
        description = "Windows shortcut (LNK) with suspicious command execution"
        author      = "PhishGuard SOC"
        severity    = "high"
        reference   = "MITRE T1204.002"

    strings:
        $lnk_magic = { 4C 00 00 00 01 14 02 00 }
        $ps         = "powershell" nocase
        $cmd        = "cmd.exe" nocase
        $wscript    = "wscript" nocase

    condition:
        $lnk_magic and 1 of ($ps, $cmd, $wscript)
}


rule SuspiciousExeDropper {
    meta:
        description = "Executable with embedded PE or download patterns"
        author      = "PhishGuard SOC"
        severity    = "critical"
        reference   = "MITRE T1027.002"

    strings:
        $pe_magic  = { 4D 5A }
        $dl1       = "URLDownloadToFile" nocase
        $dl2       = "WinHttpOpen" nocase
        $dl3       = "InternetOpenUrl" nocase
        $dl4       = "DownloadFile" nocase

    condition:
        $pe_magic at 0 and 1 of ($dl*)
}


rule JavaScriptObfuscated {
    meta:
        description = "JavaScript file with heavy obfuscation markers"
        author      = "PhishGuard SOC"
        severity    = "medium"
        reference   = "MITRE T1059.007"

    strings:
        $eval1  = "eval(" nocase
        $eval2  = "eval ('" nocase
        $unescape = "unescape(" nocase
        $decode = "atob(" nocase
        $fcode  = "fromCharCode" nocase
        $long_str = /[a-zA-Z0-9+\/]{500,}/

    condition:
        $eval1 and ($unescape or $decode or $fcode or $long_str)
}
