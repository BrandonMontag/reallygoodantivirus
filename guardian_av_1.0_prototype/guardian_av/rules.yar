rule Suspicious_PowerShell_Encoded {
    strings:
        $a = "-enc" ascii nocase
        $b = "powershell" ascii nocase
        $c = "FromBase64String" ascii nocase
    condition:
        2 of them
}

rule Suspicious_LOLBIN_Decode {
    strings:
        $a = "certutil" ascii nocase
        $b = "-decode" ascii nocase
        $c = "rundll32" ascii nocase
        $d = "regsvr32" ascii nocase
    condition:
        2 of them
}
