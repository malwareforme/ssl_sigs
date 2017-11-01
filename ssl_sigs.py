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
# Suricata rule:
# alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)"; flow:established:from_server; content"|55 04 03|";
# content:"|11|something.bad.com"; distance:1; within:18; reference:md5,31d7c3e829be03400641f80b821ef728; reference:md5,0421008445828ceb46f496700a5fa65e;
# classtype:trojan-activity; sid:100000001; rev:1;)
#
# Snort rule:
# alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"ET TROJAN Observed Malicious SSL Cert (Ursnif Injects)"; flow:established:from_server; content"|55 04 03|"; 
# content:"|11|something.bad.com"; distance:1; within:18; reference:md5,31d7c3e829be03400641f80b821ef728; reference:md5,0421008445828ceb46f496700a5fa65e; 
# classtype:trojan-activity; sid:100000001; rev:1;)

import argparse,re

def main():
	parser = argparse.ArgumentParser(description='Create Suricata/Snort SSL Certificate Signatures')
	parser.add_argument('-d','--domain', help='Domain name',required=True,default="")
	parser.add_argument('-m','--message', help='Provide full signature message, e.g. ET TROJAN Malicious SSL Cert (Ursnif Injects)',required=True,default="")
	parser.add_argument('-r','--reference', help='Provide a md5 or url reference, or list of references separated by a |',required=False,default="")
	parser.add_argument('-c','--classtype', help='Provide signature classtype (default: trojan-activity)',required=False,default="trojan-activity")
	parser.add_argument('-s','--sid', help='Provide starting sid number (default: 10000000)',required=False,default="10000000")

	args = parser.parse_args()


	domain = args.domain
	message = args.message
	references = args.reference
	classtype = args.classtype
	sid = int(args.sid)

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

	rule_stub_start_suri = 'alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"%s"; flow:established,from_server; content:"|55 04 03|"; ' % message
	rule_stub_start_suri_current = 'alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"%s"; flow:established,from_server; tls_cert_subject; ' % message
	rule_stub_content_suri_current = 'content:"%s"; fast_pattern; nocase; isdataat!1,relative; ' % domain
	rule_stub_len = 'content:"%s%s"; distance:1; ' % (domain_len,domain) 
	rule_stub_within = 'within:%s; fast_pattern; ' % within
	rule_stub_end =  '%sclasstype:%s; sid:%s; rev:1;)' % (reference,classtype,sid)
	sid += 1

	rule_stub_start_snort = 'alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"%s"; flow:established,from_server; content:"|55 04 03|"; ' % message

	print '#Suricata 3.2.+ rule:\r\n' + rule_stub_start_suri_current + rule_stub_content_suri_current + rule_stub_end + '\r\n'
	print '\r\n#Suricata 1.3+ rule:\r\n' + rule_stub_start_suri + rule_stub_len + rule_stub_within + rule_stub_end + '\r\n'
	print '\r\n#Snort 2.9+ rule:\r\n' + rule_stub_start_snort + rule_stub_len + rule_stub_within + rule_stub_end + '\r\n'



if __name__ == '__main__':
	main()
