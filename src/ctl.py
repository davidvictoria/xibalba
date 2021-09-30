import requests
import json
from urllib.parse import quote
import csv
import pendulum
import urllib3

urllib3.disable_warnings()

def get_transparency_report(domain, include_subdomains = True):
	#Empty list for save certs list
	all_domains        = []
	all_issuers        = []

	include_subdomains = 'true' if include_subdomains == True else 'false'

	#On first request
	req = requests.get('https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_subdomains='+include_subdomains+'&domain='+domain)
	#Fix: Delete first 6 chars (for json parse)
	response = req.text[6:]

	response = json.loads(response)

	next_key = response[0][3][1]

	total_pages = response[0][3][4]
	certs       = response[0][1]
	issuers     = response[0][2]

	for issuer in issuers:
		all_issuers.append(issuer)

	for cert in certs:
		all_domains.append(cert)

	#Iterate all elements
	for i in range(2, total_pages+1):
		req      = requests.get('https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch/page?p='+next_key)
		response = req.text[6:]

		response = json.loads(response)

		next_key    = response[0][3][1]
		total_pages = response[0][3][4]
		certs       = response[0][1]

		for cert in certs:
			all_domains.append(cert)

	final_list = {}

	for domain in all_domains:
		subject     = domain[1]
		domain_hash = domain[5]
		domain_hash = domain_hash.encode('utf-8')
		domain_hash = quote(domain_hash)
		req      = requests.get('https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certbyhash?hash='+domain_hash)

		response = req.text[6:]
		response = json.loads(response)

		serial        = response[0][1][0]
		common_name   = response[0][1][1]
		issuer        = response[0][1][2]
		vigence_since = response[0][1][3]
		vigence_to    = response[0][1][4]
		dns_names     = response[0][1][7]
		lists         = response[0][2]

		full_info_domain = {'subject': subject, 'serial': serial, 'common_name':common_name, 'issuer':issuer, 'vigence_since':vigence_since, 'vigence_to':vigence_to, 'dns_names': dns_names, 'lists': lists, 'hash': domain_hash}
		
		if serial not in final_list:
			final_list[serial] = full_info_domain
		else:
			for list_ctl in lists: 
				final_list[serial]['lists'].append(list_ctl)

	print('\tSe indentificaron {} certificados.'.format(len(final_list)))


	return final_list

def get_all_targets(results):
	
	domains = []

	for result in results.items():
		result = result[1]
		subject = result['subject']

		if subject not in domains:
			domains.append(subject)

		for dns_names in result['dns_names']:
			if dns_names not in domains:
				domains.append(dns_names)

	print('\tSe indentificaron {} dominios relacionados.'.format(len(dns_names)))

	return domains

def generate_ctl_csv(domain_to_check, results):

	header = ['Dominio principal', 'No. de serie', 'Emisor', 'Vigencia desde', 'Vigencia hasta', 'Dominios alternos', 'Publicado en', 'Estado', 'Dias de vigencia', 'Liga a Google CTL']

	now = pendulum.now()

	print('\tCreando archivo results_'+domain_to_check+'.csv')

	with open('results_'+domain_to_check+'.csv', 'w', newline="", encoding='utf-8') as f:
		writer = csv.writer(f)
		# write the header
		writer.writerow(header)
		# write the data
		for result in results.items():

			result = result[1]

			since = pendulum.from_timestamp((result['vigence_since'] / 1000))
			to    = pendulum.from_timestamp((result['vigence_to'] / 1000))

			if now > to:
				status = 'Expirado'
				remaining_days = '-'
			else:
				status = 'Vigente'
				remaining_days = now.diff(to).in_days()

			dns_names = '\r\n'.join(result['dns_names'])

			ctl = []

			for ctl_list in result['lists']:
				ctl.append(ctl_list[0]+' ('+str(ctl_list[2])+')')

			ctls = '\r\n'.join(ctl)

			ctl_url = 'https://transparencyreport.google.com/https/certificates/'+result['hash']

			writer.writerow([result['subject'], result['serial'], result['issuer'], since, to, dns_names, ctls, status, remaining_days, ctl_url])

def generate_subdomains_csv(domain_to_check, all_domains):

	results = []

	for domain in all_domains:

		ip           = ''
		sts          = ''
		server       = ''
		https_enable = 'No'
		http_enable  = 'No'

		try:
			r       = requests.get('https://'+domain, timeout=3, stream=True)
			ip      = r.raw.connection.sock.getpeername()
			headers = r.headers

			https_enable = 'Si'

			ip = ip[0]

			try:
				sts = headers['Strict-Transport-Security']
			except:
				sts = ''

			try:
				server = headers['Server']
			except:
				server = ''

		except:
			try:
				r = requests.get('https://'+domain, timeout=3, stream=True, verify=False)
				https_enable = 'Conexion lograda con error TLS' 
			except:
				https_enable = 'No'

		try:
			r = requests.get('http://'+domain, timeout=3, stream=True)
			http_enable = 'Si'
		except:
			http_enable = 'No'

		results.append([domain, https_enable, http_enable, ip, server, sts])

	header = ['Dominio', 'Accesible a traves de HTTPS', 'Accesible a traves de HTTP', 'IP', 'Servidor', 'Valor STS']

	print('\tCreando archivo results_subdomains_'+domain_to_check+'.csv')

	with open('subdomains_'+domain_to_check+'.csv', 'w', newline="", encoding='utf-8') as f:
		writer = csv.writer(f)
		# write the header
		writer.writerow(header)
		# write the data
		for result in results:
			writer.writerow(result)
