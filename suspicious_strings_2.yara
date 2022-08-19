rule suspicious_strings
{
strings:
    $mz = {4D 5A}
    $a = "Synflooding" ascii wide nocase
    $b = "Portscanner" ascii wide nocase
    $c = "Keylogger" ascii wide nocase
condition:
    ($mz at 0) and ($a or $b or $c) 
}