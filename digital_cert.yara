rule mal_digital_cert_9002_rat
{
meta:
    description = "Detects malicious digital certificates used by RAT 9002"
    ref = "http://blog.cylance.com/another-9002-trojan-variant"

strings:
    $mz = { 4D 5A }
    $a = { 45 6e 96 7a 81 5a a5 cb b9 9f b8 6a ca 8f 7f 69 }

condition:
    ($mz at 0) and ($a in (1024..filesize)) 
}