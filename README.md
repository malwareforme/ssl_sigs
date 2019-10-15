ssl_sigs.py

Create basic Suricata and Snort signatures to detect an inbound SSL Cert for a single domain as well as a domain in the outbound TLS SNI field. This includes support for Suricata 1.3+, 3.2+, 4+, and 5 as well as Snort 2.9+

Thanks to Darien Huss and his work on a DNS signature script[1] and another thanks to Travis Green.

[1]https://github.com/darienhuss/dns_sigs

$ python ssl_sigs.py -d something.bad.com -m "Ursnif CnC" -s 100000000 -r 31d7c3e829be03400641f80b821ef728 

OUTPUT:
```
#=========================[Certificate Signatures]=========================#

#Suricata 5.0 SSL Cert Rule:
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Observed Malicious SSL Cert (Ursnif CnC)"; flow:established,to_client; tls.cert_subject; content:"CN=something.bad.com"; nocase; endswith; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:domain-c2; sid:100000000; rev:1;)

#Suricata 3.2.+ SSL Cert Rule:
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Observed Malicious SSL Cert (Ursnif CnC)"; flow:established,to_client; tls_cert_subject; content:"CN=something.bad.com"; nocase; isdataat:!1,relative; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:trojan-activity; sid:100000000; rev:1;)

#Suricata 1.3+ SSL Cert Rule:
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Observed Malicious SSL Cert (Ursnif CnC)"; flow:established,to_client; content:"|55 04 03|"; content:"|11|something.bad.com"; distance:1; within:18; fast_pattern; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:trojan-activity; sid:100000000; rev:1;)

#Snort 2.9+ SSL Cert Rule:
alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET MALWARE Observed Malicious SSL Cert (Ursnif CnC)"; flow:established,to_client; content:"|55 04 03|"; content:"|11|something.bad.com"; distance:1; within:18; fast_pattern; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:trojan-activity; sid:100000000; rev:1;)

Rule Description:
This will alert on an SSL cert for a domain hosting Ursnif CnC.

```

You can also include a signature for the domain as it appears in the TLS SNI buffer by appending '--sni' like so:

$ python ssl_sigs.py -d something.bad.com -m "Ursnif CnC" -s 100000000 -r 31d7c3e829be03400641f80b821ef728 --sni

```
#=========================[Certificate Signatures]=========================#

#Suricata 5.0 SSL Cert Rule:
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Observed Malicious SSL Cert (Ursnif CnC)"; flow:established,to_client; tls.cert_subject; content:"CN=something.bad.com"; nocase; endswith; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:domain-c2; sid:100000000; rev:1;)

#Suricata 3.2.+ SSL Cert Rule:
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Observed Malicious SSL Cert (Ursnif CnC)"; flow:established,to_client; tls_cert_subject; content:"CN=something.bad.com"; nocase; isdataat:!1,relative; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:trojan-activity; sid:100000000; rev:1;)

#Suricata 1.3+ SSL Cert Rule:
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Observed Malicious SSL Cert (Ursnif CnC)"; flow:established,to_client; content:"|55 04 03|"; content:"|11|something.bad.com"; distance:1; within:18; fast_pattern; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:trojan-activity; sid:100000000; rev:1;)

#Snort 2.9+ SSL Cert Rule:
alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET MALWARE Observed Malicious SSL Cert (Ursnif CnC)"; flow:established,to_client; content:"|55 04 03|"; content:"|11|something.bad.com"; distance:1; within:18; fast_pattern; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:trojan-activity; sid:100000000; rev:1;)

Rule Description:
This will alert on an SSL cert for a domain hosting Ursnif CnC.

#=========================[SNI Signatures]=========================#

#Suricata 5.0 TLS SNI Cert Rule:
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Observed Ursnif CnC Domain in TLS SNI"; flow:established,to_server; tls_sni; content:"something.bad.com"; bsize:17; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:domain-c2; sid:100000001; rev:1;)

#Suricata 3.2+ TLS SNI Cert Rule:
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Observed Ursnif CnC Domain in TLS SNI"; flow:established,to_server; tls_sni; content:"something.bad.com"; depth:17; isdataat:!1,relative; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:trojan-activity; sid:100000001; rev:1;)

#Suricata 1.3+ TLS SNI Cert Rule:
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Observed Ursnif CnC Domain in TLS SNI"; flow:established,to_server; content:"|00 00 11|something.bad.com|00|"; fast_pattern; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:trojan-activity; sid:100000001; rev:1;)

#Snort 2.9+ TLS SNI Cert Rule:
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"ET MALWARE Observed Ursnif CnC Domain in TLS SNI"; flow:established,to_server; content:"|00 00 11|something.bad.com|00|"; fast_pattern; reference:md5,31d7c3e829be03400641f80b821ef728; classtype:trojan-activity; sid:100000001; rev:1;)

Rule Description:
This will alert on a Ursnif CnC domain observed in the TLS SNI.

```
