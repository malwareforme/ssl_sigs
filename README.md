ssl_sigs.py

Create Suricata and Snort signatures to detect an inbound SSL Cert for a single domain.

Mega thanks to Darien Huss and his work on a DNS signature script[1] which is where most of this code was ripped from. Another big thanks to Travis Green.

[1]https://github.com/darienhuss/dns_sigs

Example: $ python ssl_sigs.py -d something.bad.com -m "ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)" -s 100000000 -r "31d7c3e829be03400641f80b821ef728|0421008445828ceb46f496700a5fa65e" 

OUTPUT:

#Suricata 3.2.+ rule:
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)"; flow:established,from_server; tls_cert_subject; content:"something.bad.com"; nocase; isdataat!1,relative; reference:md5,31d7c3e829be03400641f80b821ef728; reference:md5,0421008445828ceb46f496700a5fa65e; classtype:trojan-activity; sid:100000000; rev:1;)


#Suricata 1.3+ rule:
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)"; flow:established,from_server; content:"|55 04 03|"; content:"|11|something.bad.com"; distance:1; within:18; reference:md5,31d7c3e829be03400641f80b821ef728; reference:md5,0421008445828ceb46f496700a5fa65e; classtype:trojan-activity; sid:100000000; rev:1;)


#Snort 2.9+ rule:
alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)"; flow:established,from_server; content:"|55 04 03|"; content:"|11|something.bad.com"; distance:1; within:18; reference:md5,31d7c3e829be03400641f80b821ef728; reference:md5,0421008445828ceb46f496700a5fa65e; classtype:trojan-activity; sid:100000000; rev:1;)
