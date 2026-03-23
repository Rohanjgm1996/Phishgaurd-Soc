/*
  PhishGuard SOC — Phishing Detection YARA Rules
  Defensive use only. Detects common phishing patterns in email bodies and attachments.
  Rules are intentionally conservative to reduce false positives in a SOC context.
*/

rule PhishingCredentialHarvest {
    meta:
        description = "Detects credential harvesting patterns in email/HTML content"
        author      = "PhishGuard SOC"
        severity    = "high"
        reference   = "MITRE T1056"

    strings:
        $h1 = "verify your account" nocase
        $h2 = "confirm your identity" nocase
        $h3 = "update your password" nocase
        $h4 = "your account has been suspended" nocase
        $h5 = "unusual sign-in activity" nocase
        $h6 = "click here to restore" nocase
        $h7 = "your account will be closed" nocase
        $u1 = "password" nocase
        $u2 = "username" nocase
        $u3 = "login" nocase

    condition:
        2 of ($h*) or (1 of ($h*) and 2 of ($u*))
}


rule PhishingUrgencyLanguage {
    meta:
        description = "Detects urgency and fear-inducing language common in phishing"
        author      = "PhishGuard SOC"
        severity    = "medium"

    strings:
        $u1 = "act immediately" nocase
        $u2 = "limited time" nocase
        $u3 = "expires in 24 hours" nocase
        $u4 = "immediate action required" nocase
        $u5 = "your account is at risk" nocase
        $u6 = "security breach" nocase
        $u7 = "unauthorized access detected" nocase

    condition:
        2 of them
}


rule SuspiciousIPBasedURL {
    meta:
        description = "Detects URLs using raw IP addresses — common in phishing"
        author      = "PhishGuard SOC"
        severity    = "high"
        reference   = "MITRE T1566.002"

    strings:
        $ip1 = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $ip2 = /http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

    condition:
        any of them
}


rule SuspiciousBase64InMacro {
    meta:
        description = "Detects large Base64 blobs in VBA macro context — possible payload staging"
        author      = "PhishGuard SOC"
        severity    = "high"
        reference   = "MITRE T1027"

    strings:
        $b64  = /[A-Za-z0-9+\/]{200,}={0,2}/
        $vba1 = "AutoOpen" nocase
        $vba2 = "Document_Open" nocase
        $vba3 = "Shell" nocase
        $vba4 = "CreateObject" nocase

    condition:
        $b64 and 1 of ($vba*)
}


rule PowerShellDownloader {
    meta:
        description = "Detects PowerShell download cradle patterns"
        author      = "PhishGuard SOC"
        severity    = "critical"
        reference   = "MITRE T1059.001"

    strings:
        $ps1 = "Invoke-Expression" nocase
        $ps2 = "IEX" fullword nocase
        $ps3 = "DownloadString" nocase
        $ps4 = "DownloadFile" nocase
        $ps5 = "WebClient" nocase
        $ps6 = "Net.WebClient" nocase
        $ps7 = "bitsadmin" nocase
        $ps8 = "certutil" nocase

    condition:
        2 of them
}


rule SuspiciousVBScriptShell {
    meta:
        description = "Detects VBScript patterns used for shell execution"
        author      = "PhishGuard SOC"
        severity    = "high"
        reference   = "MITRE T1059.005"

    strings:
        $v1 = "WScript.Shell" nocase
        $v2 = "CreateObject" nocase
        $v3 = "Shell.Application" nocase
        $v4 = "cmd.exe" nocase
        $v5 = "powershell" nocase
        $v6 = "Run(" nocase

    condition:
        ($v1 or $v3) and ($v4 or $v5 or $v6)
}


rule HTMLFormCredentialPhish {
    meta:
        description = "Detects HTML pages with login forms — may be phishing landing pages"
        author      = "PhishGuard SOC"
        severity    = "medium"

    strings:
        $f1 = "<form" nocase
        $f2 = "type=\"password\"" nocase
        $f3 = "type='password'" nocase
        $f4 = "<input" nocase
        $f5 = "action=" nocase

    condition:
        $f1 and ($f2 or $f3) and $f4 and $f5
}


rule PDFWithJavaScript {
    meta:
        description = "Detects PDF files containing JavaScript — common in malicious PDFs"
        author      = "PhishGuard SOC"
        severity    = "high"
        reference   = "MITRE T1566.001"

    strings:
        $pdf_hdr = "%PDF-"
        $js1     = "/JS"
        $js2     = "/JavaScript"
        $launch  = "/Launch"
        $action  = "/OpenAction"

    condition:
        $pdf_hdr and ($js1 or $js2 or $launch or $action)
}


rule SuspiciousArchiveDoubleExt {
    meta:
        description = "Detects filenames with double extensions inside archives"
        author      = "PhishGuard SOC"
        severity    = "high"
        reference   = "MITRE T1036.007"

    strings:
        $de1 = ".pdf.exe" nocase
        $de2 = ".doc.exe" nocase
        $de3 = ".jpg.exe" nocase
        $de4 = ".png.exe" nocase
        $de5 = ".txt.exe" nocase
        $de6 = ".pdf.bat" nocase
        $de7 = ".doc.vbs" nocase

    condition:
        any of them
}
