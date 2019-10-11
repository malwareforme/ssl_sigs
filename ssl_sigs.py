#!/usr/bin/env python
#
# ssl_sigs.py
# Create Suricata and Snort signatures to detect an inbound SSL Cert for a single domain.
#
# Mega thanks to Darien Huss[1] and his work on a DNS signature script which is where most of this code was ripped from. Another big thanks to Travis Green for assistance.
# [1]https://github.com/darienhuss/dns_sigs
#
# Example: $ python ssl_sigs.py -d something.bad.com -m "Ursnif Injects" -s 100000000 -r "31d7c3e829be03400641f80b821ef728|0421008445828ceb46f496700a5fa65e" 


import argparse,re

def main():
	parser = argparse.ArgumentParser(description='Create Basic Suricata/Snort SSL Certificate Signatures')
	parser.add_argument('-d','--domain', help='Domain name',required=True,default="")
	parser.add_argument('-m','--message', help='Malware name and or Activity (e.g. "Urnsif Injects")',required=True,default="")
	parser.add_argument('-r','--reference', help='Provide a md5 or url reference, or list of references separated by a |',required=False,default="")
	parser.add_argument('-c','--classtype', help='Provide signature classtype (default: domain-c2)',required=False,default="domain-c2")
	parser.add_argument('-s','--sid', help='Provide starting sid number (default: 10000000)',required=False,default="10000000")
	parser.add_argument('-t','--sni', help='Include TLS SNI signatures also',action="store_true",required=False,default="")
	parser.add_argument('-C','--category', help='Add a category for this rule (default: MALWARE',required=False,default="MALWARE")
	parser.add_argument('-n','--rulesetname', help='Add a custom ruleset name (default: ET', required=False,default="ET")
	parser.add_argument('-p','--pro', help='mod sigs for pro', action="store_true",required=False,default="")

	args = parser.parse_args()


	domain = args.domain
	message = args.message
	references = args.reference
	classtype = args.classtype
	if classtype:
		classtype = "domain-c2"
		legacy_classtype = "trojan-activity"
	sid = int(args.sid)
	sni = args.sni
	category = args.category
	rulesetname = args.rulesetname
	pro = args.pro

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
	domain_len_bsize = len(domain)
	tls_sid = sid + 1

	domain_defang = re.sub(r"\.", " .", domain)

	rule_stub_start_suri = 'alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"%s %s Observed Malicious SSL Cert (%s)"; flow:established,to_client; content:"|55 04 03|"; ' % (rulesetname,category,message)
	pro_rule_stub_start_suri = 'alert tls $EXTERNAL_NET any -> $HOME_NET any (flow:established,to_client; content:"|55 04 03|"; '
	rule_stub_start_suri_current = 'alert tls $EXTERNAL_NET any -> $HOME_NET any (flow:established,to_client; tls_cert_subject; '
	pro_rule_stub_start_suri_current = 'alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"%s %s Observed Malicious SSL Cert (%s)"; flow:established,to_client; tls_cert_subject; ' % (rulesetname,category,message)
	rule_stub_start_suri5 = 'alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"%s %s Observed Malicious SSL Cert (%s)"; flow:established,to_client; tls.cert_subject; ' % (rulesetname,category,message)
	rule_stub_start_snort = 'alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"%s %s Observed Malicious SSL Cert (%s)"; flow:established,to_client; content:"|55 04 03|"; ' % (rulesetname,category,message)
	pro_rule_stub_start_snort = 'alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (flow:established,to_client; content:"|55 04 03|"; '
	rule_stub_content_suri5_current = 'content:"CN=%s"; nocase; endswith; ' % domain
	rule_stub_content_suri_current = 'content:"CN=%s"; nocase; isdataat:!1,relative; ' % domain
	pro_rule_stub_content_suri_current = 'content:"CN=%s"; nocase; isdataat:!1,relative;)' % domain
	rule_stub_len = 'content:"%s%s"; distance:1; ' % (domain_len,domain) 
	rule_stub_within = 'within:%s; fast_pattern; ' % within
	pro_rule_stub_within = 'within:%s; fast_pattern;)' % within
	rule_stub_end =  '%sclasstype:%s; sid:%s; rev:1;)' % (reference,classtype,sid)
	legacy_rule_stub_end =  '%sclasstype:%s; sid:%s; rev:1;)' % (reference,legacy_classtype,sid)
	sid += 1

#SSL Cert stuff

	print '\r\n#=========================[Certificate Signatures]=========================#\r\n'

	if pro:
		print '#Suricata 5.0 SSL Cert Rule:\r\n' + rule_stub_start_suri5 + rule_stub_content_suri5_current + rule_stub_end + '\r\n'
		print '#Suricata 3.2+ SSL Cert Rule (pro ver):\r\n' + rule_stub_start_suri_current + pro_rule_stub_content_suri_current + '\r\n'
		print '#Suricata 1.3+ SSL Cert Rule (pro ver):\r\n' + pro_rule_stub_start_suri + rule_stub_len + pro_rule_stub_within + '\r\n'
		print '#Snort 2.9+ SSL Cert Rule (pro ver):\r\n' + pro_rule_stub_start_snort + rule_stub_len + pro_rule_stub_within + '\r\n'
		print 'Rule Description:\r\n' + 'This will alert on an SSL cert for a domain hosting %s.' % message

	else:
		print '#Suricata 5.0 SSL Cert Rule:\r\n' + rule_stub_start_suri5 + rule_stub_content_suri5_current + rule_stub_end + '\r\n'
		print '#Suricata 3.2.+ SSL Cert Rule:\r\n' + rule_stub_start_suri_current + rule_stub_content_suri_current + legacy_rule_stub_end + '\r\n'
		print '#Suricata 1.3+ SSL Cert Rule:\r\n' + rule_stub_start_suri + rule_stub_len + rule_stub_within + legacy_rule_stub_end + '\r\n'
		print '#Snort 2.9+ SSL Cert Rule:\r\n' + rule_stub_start_snort + rule_stub_len + rule_stub_within + legacy_rule_stub_end + '\r\n'
		print 'Rule Description:\r\n' + 'This will alert on an SSL cert for a domain hosting %s.' % message 

#TLSSNI stuff

	if sni and pro:
		tls_sni_rule_stub_start_suri = 'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"%s %s Observed %s Domain in TLS SNI"; flow:established,to_server; ' % (rulesetname,category,message)
		pro_tls_sni_rule_stub_start_suri = 'alert tls $HOME_NET any -> $EXTERNAL_NET any (flow:established,to_server; '
		tls_sni_rule_stub_start_snort = 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"%s %s Observed %s Domain in TLS SNI"; flow:established,to_server; ' % (rulesetname,category,message)
		pro_tls_sni_rule_stub_start_snort = 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (flow:established,to_server; '
		rule_stub_content_suri5 = 'tls.sni; content:"%s"; bsize:%s; ' % (domain,domain_len_bsize)
		rule_stub_content_suri_4 = 'tls_sni; content:"%s"; isdataat:!1,relative; ' % domain
		pro_rule_stub_content_suri_4 = 'tls_sni; content:"%s"; isdataat:!1,relative;)' % domain
		rule_stub_content_snort_suri2 = 'content:"%s%s|00|"; fast_pattern; ' % (domain_len_tlssni,domain)
		pro_rule_stub_content_snort_suri2 = 'content:"%s%s|00|"; fast_pattern;)' % (domain_len_tlssni,domain)
		rule_stub_end_tlssni = '%sclasstype:%s; sid:%s; rev:1;)' % (reference,classtype,tls_sid)
		legacy_rule_stub_end_tlssni = '%sclasstype:%s; sid:%s; rev:1;)' % (reference,legacy_classtype,tls_sid)

		print '\r\n#=========================[SNI Signatures]=========================#\r\n'
		print '#Suricata 5.0 TLS SNI Cert Rule:\r\n' + tls_sni_rule_stub_start_suri + rule_stub_content_suri5 + rule_stub_end_tlssni + '\r\n'
		print '#Suricata 3.2+ TLS SNI Cert Rule:\r\n' + tls_sni_rule_stub_start_suri + pro_rule_stub_content_suri_4 + '\r\n'
		print '#Suricata 1.3+ TLS SNI Cert Rule:\r\n' + tls_sni_rule_stub_start_suri + pro_rule_stub_content_snort_suri2 + '\r\n'
		print '#Snort 2.9+ TLS SNI Cert Rule:\r\n' + tls_sni_rule_stub_start_snort + pro_rule_stub_content_snort_suri2 + '\r\n'
		print 'Rule Description:\r\n' + 'This will alert on a %s domain observed in the TLS SNI.' % message

	if sni and not pro:
		tls_sni_rule_stub_start_suri = 'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"%s %s Observed %s Domain in TLS SNI"; flow:established,to_server; ' % (rulesetname,category,message)
		tls_sni_rule_stub_start_snort = 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"%s %s Observed %s Domain in TLS SNI"; flow:established,to_server; ' % (rulesetname,category,message)
		rule_stub_content_suri5 = 'tls_sni; content:"%s"; bsize:%s; ' % (domain,domain_len_bsize)
		rule_stub_content_suri_4 = 'tls_sni; content:"%s"; isdataat:!1,relative; ' % domain
		rule_stub_content_snort_suri2 = 'content:"%s%s|00|"; fast_pattern; ' % (domain_len_tlssni,domain)
		rule_stub_end_tlssni = '%sclasstype:%s; sid:%s; rev:1;)' % (reference,classtype,tls_sid)
		legacy_rule_stub_end_tlssni = '%sclasstype:%s; sid:%s; rev:1;)' % (reference,legacy_classtype,tls_sid)

		print '\r\n#=========================[SNI Signatures]=========================#\r\n'
		print '#Suricata 5.0 TLS SNI Cert Rule:\r\n' + tls_sni_rule_stub_start_suri + rule_stub_content_suri5 + rule_stub_end_tlssni + '\r\n'
		print '#Suricata 3.2+ TLS SNI Cert Rule:\r\n' + tls_sni_rule_stub_start_suri + rule_stub_content_suri_4 + legacy_rule_stub_end_tlssni + '\r\n'
		print '#Suricata 1.3+ TLS SNI Cert Rule:\r\n' + tls_sni_rule_stub_start_suri + rule_stub_content_snort_suri2 + legacy_rule_stub_end_tlssni + '\r\n'
		print '#Snort 2.9+ TLS SNI Cert Rule:\r\n' + tls_sni_rule_stub_start_snort + rule_stub_content_snort_suri2 + legacy_rule_stub_end_tlssni + '\r\n'
		print 'Rule Description:\r\n' + 'This will alert on a %s domain observed in the TLS SNI.' % message 
		print '\r\n'
	
	else:
		print '\r\n'


if __name__ == '__main__':
	main()