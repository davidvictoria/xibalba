from src.dnstwist import dnstwist
import requests
import csv
import whois

def fuzz(domain):
	fuzz = dnstwist.DomainFuzz(domain)
	fuzz.generate()
	domains = fuzz.domains

	print('\tSe indentificaron {} probables dominios.'.format(len(domains)))

	return domains


def check(domains):

	domains_review = []

	for domain in domains:

		fuzzer      = domain['fuzzer']
		domain_name = domain['domain-name']

		try:
			r       = requests.get('http://'+domain_name, timeout=3, stream=True)
			ip      = r.raw.connection.sock.getpeername()
			headers = r.headers

			ip = ip[0]
			
			try:
				server = headers['Server']
			except:
				server = ''

			resolve = 'Si'

		except:
			server  = ''
			ip      = ''
			resolve = 'No'


		domains_review.append([domain_name, fuzzer, resolve, ip, server])

	return domains_review

def create_csv(domain, domains):
	header = ['Dominio', 'Fuzzer', 'Resuelve', 'IP', 'Servidor']

	print('\tCreando archivo typosquatting_'+domain+'.csv')

	with open('typosquatting_'+domain+'.csv', 'w', newline="", encoding='utf-8') as f:
		writer = csv.writer(f)
		# write the header
		writer.writerow(header)
		# write the data
		for domain in domains:
			writer.writerow(domain)


def who_is(domain_name, domains):

	whois_txt = '' 

	for domain in domains:
		if domain[2] == 'Si':
			w = str(whois.whois(domain[0]))

			whois_txt += '[-----'+domain_name+'-----]\n'
			whois_txt += w+'\n\n'

	print('\tCreando archivo whois_typosquatting_'+domain_name+'.txt')

	with open('whois_typosquatting_'+domain_name+'.txt', 'w') as f:
		f.write(whois_txt)

	return whois_txt