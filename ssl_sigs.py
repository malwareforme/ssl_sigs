#!/usr/bin/env python
#
# ssl_sigs.py
# Create Suricata and Snort signatures to detect an inbound SSL Cert for a single domain.
#
# Mega thanks to Darien Huss[1] and his work on a DNS signature script which is where most of this code was ripped from. Another big thanks to Travis Green for assistance.
# [1]https://github.com/darienhuss/dns_sigs
#
# Example: $ python ssl_sigs.py -d something.bad.com -m "ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)" -s 100000000 -r "31d7c3e829be03400641f80b821ef728|0421008445828ceb46f496700a5fa65e" 
#
# OUTPUT:
#=========================[TLS/SSL CERT]=========================
#
#Suricata 3.2.+ SSL Cert Rule:
#alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)"; flow:established,to_client; tls_cert_subject; content:"CN=something.bad.com"; nocase; isdataat:!1,relative; reference:md5,31d7c3e829be03400641f80b821ef728; reference:md5,0421008445828ceb46f496700a5fa65e; classtype:trojan-activity; sid:100000000; rev:1;)
#
#
#Suricata 1.3+ SSL Cert Rule:
#alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)"; flow:established,to_client; content:"|55 04 03|"; content:"|11|something.bad.com"; distance:1; within:18; fast_pattern; reference:md5,31d7c3e829be03400641f80b821ef728; reference:md5,0421008445828ceb46f496700a5fa65e; classtype:trojan-activity; sid:100000000; rev:1;)
#
#
#Snort 2.9+ SSL Cert Rule:
#alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)"; flow:established,to_client; content:"|55 04 03|"; content:"|11|something.bad.com"; distance:1; within:18; fast_pattern; reference:md5,31d7c3e829be03400641f80b821ef728; reference:md5,0421008445828ceb46f496700a5fa65e; classtype:trojan-activity; sid:100000000; rev:1;)
#
# You can also use -t/--sni to also print the equivilent TLS SNI signaures (useful for detecting the cert via the outbound request incase domain is down/cert is gone)
#
# $ python ssl_sigs.py -d something.bad.com -m "ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)" -s 100000000 -r "31d7c3e829be03400641f80b821ef728|0421008445828ceb46f496700a5fa65e" -t
#
# <snip>
#
#=========================[TLS SNI]=========================
#
#Suricata 3.2+ TLS SNI Cert Rule:
#alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)"; flow:established:to_server; tls_sni; content:"something.bad.com"; isdataat:!1,relative; reference:md5,31d7c3e829be03400641f80b821ef728; reference:md5,0421008445828ceb46f496700a5fa65e; classtype:trojan-activity; sid:100000000; rev:1;)
#
#Suricata 1.3+ TLS SNI Cert Rule:
#alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)"; flow:established:to_server; content:"|00 00 11|something.bad.com|00|"; fast_pattern; reference:md5,31d7c3e829be03400641f80b821ef728; reference:md5,0421008445828ceb46f496700a5fa65e; classtype:trojan-activity; sid:100000000; rev:1;)
#
#Snort 2.9+ TLS SNI Cert Rule:
#alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)"; flow:established,to_server; content:"|00 00 11|something.bad.com|00|"; fast_pattern; reference:md5,31d7c3e829be03400641f80b821ef728; reference:md5,0421008445828ceb46f496700a5fa65e; classtype:trojan-activity; sid:100000000; rev:1;)
#

import argparse,re

def main():
	parser = argparse.ArgumentParser(description='Create Suricata/Snort SSL Certificate Signatures')
	parser.add_argument('-d','--domain', help='Domain name',required=True,default="")
	parser.add_argument('-m','--message', help='Provide full signature message, e.g. ET TROJAN Malicious SSL Cert (Ursnif Injects)',required=True,default="")
	parser.add_argument('-r','--reference', help='Provide a md5 or url reference, or list of references separated by a |',required=False,default="")
	parser.add_argument('-c','--classtype', help='Provide signature classtype (default: trojan-activity)',required=False,default="trojan-activity")
	parser.add_argument('-s','--sid', help='Provide starting sid number (default: 10000000)',required=False,default="10000000")
	parser.add_argument('-t','--sni', help='Include TLS SNI signatures also',action="store_true",required=False,default="")

	args = parser.parse_args()


	domain = args.domain
	message = args.message
	references = args.reference
	classtype = args.classtype
	sid = int(args.sid)
	sni = args.sni

	reference = ''
	if references:
		md5_re = re.compile('^[a-f0-9]{32}$')
		references = references.split('|')

		for ref in references	:
			if md5_re.search(ref):
				reference += 'reference:md5,%s; ' % ref
			else:
				reference += 'reference:url,%s; ' % ref
	
	domain_len = '|{:02x}|'.format(len(domain))
	within = len(domain_len + domain) - 3
	domain_len_tlssni = '|00 00 {:02x}|'.format(len(domain))

	rule_stub_start_suri = 'alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"%s"; flow:established,to_client; content:"|55 04 03|"; ' % message
	rule_stub_start_suri_current = 'alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"%s"; flow:established,to_client; tls_cert_subject; ' % message
	rule_stub_start_snort = 'alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"%s"; flow:established,to_client; content:"|55 04 03|"; ' % message
	rule_stub_content_suri_current = 'content:"CN=%s"; nocase; isdataat:!1,relative; ' % domain
	rule_stub_len = 'content:"%s%s"; distance:1; ' % (domain_len,domain) 
	rule_stub_within = 'within:%s; fast_pattern; ' % within
	rule_stub_end =  '%sclasstype:%s; sid:%s; rev:1;)' % (reference,classtype,sid)
	sid += 1

#SSL Cert stuff

	print '\r\n=========================[Certificate Signatures]=========================\r\n'
	print '#Suricata 3.2.+ SSL Cert Rule:\r\n' + rule_stub_start_suri_current + rule_stub_content_suri_current + rule_stub_end + '\r\n'
	print '#Suricata 1.3+ SSL Cert Rule:\r\n' + rule_stub_start_suri + rule_stub_len + rule_stub_within + rule_stub_end + '\r\n'
	print '#Snort 2.9+ SSL Cert Rule:\r\n' + rule_stub_start_snort + rule_stub_len + rule_stub_within + rule_stub_end + '\r\n'

#TLSSNI stuff

	if sni:
		tls_sni_rule_stub_start_suri = 'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"%s"; flow:established:to_server; ' % message
		tls_sni_rule_stub_start_snort = 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"%s"; flow:established,to_server; ' % message
		rule_stub_content_suri_4 = 'tls_sni; content:"%s"; isdataat:!1,relative; ' % domain
		rule_stub_content_snort_suri2 = 'content:"%s%s|00|"; fast_pattern; ' % (domain_len_tlssni,domain)

		print '\r\n=========================[SNI Signatures]=========================\r\n'
		print '#Suricata 3.2+ TLS SNI Cert Rule:\r\n' + tls_sni_rule_stub_start_suri + rule_stub_content_suri_4 + rule_stub_end + '\r\n'
		print '#Suricata 1.3+ TLS SNI Cert Rule:\r\n' + tls_sni_rule_stub_start_suri + rule_stub_content_snort_suri2 + rule_stub_end + '\r\n'
		print '#Snort 2.9+ TLS SNI Cert Rule:\r\n' + tls_sni_rule_stub_start_snort + rule_stub_content_snort_suri2 + rule_stub_end + '\r\n'
	else:
		print '\r\n'


if __name__ == '__main__':
	main()