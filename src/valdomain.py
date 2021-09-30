import socket
from ssl import PROTOCOL_TLSv1
from OpenSSL import SSL
import pendulum
import requests
import json
import time

def get_domains(cert):
        san = ''
        ext_count = cert.get_extension_count()
        for i in range(0, ext_count):
            ext = cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
        return san

def get_cert_info(cert):
    cert_info = {}

    cert_subject = cert.get_subject()

    subject                       = cert_subject.CN
    subject_org                   = cert_subject.O
    issuer_country                = cert.get_issuer().countryName
    issuer_organization_name      = cert.get_issuer().organizationName
    issuer_organization_unit_name = cert.get_issuer().organizationalUnitName
    issuer_common_name            = cert.get_issuer().commonName
    serial                        = str(cert.get_serial_number())
    cert_algo                     = cert.get_signature_algorithm().decode()
    cert_version                  = (cert.get_version() + 1)
    cert_domains                  = get_domains(cert)
    cert_expired                  = cert.has_expired()
    valid_from                    = cert.get_notBefore().decode('utf-8')
    valid_to                      = cert.get_notAfter().decode('utf-8')

    valid_from = pendulum.parse(valid_from, strict=False)
    valid_to   = pendulum.parse(valid_to, strict=False)
    now        = pendulum.now()

    remaining_days = (valid_to - now).days

    valid_from_string = valid_from.to_datetime_string()
    valid_to_string   = valid_to.to_datetime_string()


    cert_info = {'subject': subject, 'subject_org': subject_org, 'issuer_country': issuer_country, 'issuer_organization_name': issuer_organization_name, 'issuer_organization_unit_name': issuer_organization_unit_name, 'issuer_common_name': issuer_common_name, 'serial': serial, 'cert_algo': cert_algo, 'cert_version': cert_version, 'cert_domains': cert_domains, 'cert_expired': cert_expired, 'valid_from': valid_from_string, 'valid_to': valid_to_string, 'remaining_days': remaining_days}

    return cert_info

def get_cert(host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    osobj = SSL.Context(PROTOCOL_TLSv1)
    sock.connect((host, 443))
    oscon = SSL.Connection(osobj, sock)
    oscon.set_tlsext_host_name(host.encode())
    oscon.set_connect_state()
    oscon.do_handshake()
    cert = oscon.get_peer_certificate()
    sock.close()

    return cert

def check_sslabs(host):

    while True:
        r = requests.get('https://api.ssllabs.com/api/v3/analyze?host='+host)
        response = json.loads(r.text)

        if response['status'] == 'ERROR':
            return response['statusMessage']
            break

        if response['status'] in ['IN_PROGRESS', 'READY']:
            try:
                status = response['endpoints'][0]['statusMessage']
                ip     = response['endpoints'][0]['ipAddress']
            except:
                status = None
                ip     = None

            if status == 'Ready':
                break
            else:
                time.sleep(10)

    r = requests.get('https://api.ssllabs.com/api/v3/getEndpointData?host='+host+'&s='+ip)

    response = json.loads(r.text)

    grade            = response['grade']
    is_exceptional   = response['isExceptional']
    is_trusted       = response['details']['certChains'][0]['trustPaths'][0]['trust'][0]['isTrusted']

    try:
        trust_error      = response['details']['certChains'][0]['trustPaths'][0]['trust'][0]['trustErrorMessage']
    except:
        trust_error      = ''

    has_sct          = response['details']['hasSct']

    try:
        server_signature = response['details']['serverSignature']
    except:
        server_signature = ''

    sni_required     = 'Requerido' if response['details']['sniRequired'] == True else 'No requerido'

    hsts_policy     = response['details']['hstsPolicy']['status']
    hpkp_policy     = response['details']['hpkpPolicy']['status']

    protocols = response['details']['protocols'] 

    vuln_poodle                  = '¡Vulnerable!' if response['details']['poodle'] == True else 'No vulnerable'
    vuln_heartbleed              = '¡Vulnerable!' if response['details']['heartbleed'] == True else 'No vulnerable'
    vuln_heartbeat               = '¡Vulnerable!' if response['details']['heartbeat'] == True else 'No vulnerable'
    vuln_freak                   = '¡Vulnerable!' if response['details']['freak'] == True else 'No vulnerable'
    vuln_logjam                  = '¡Vulnerable!' if response['details']['logjam'] == True else 'No vulnerable'
    vuln_drownVulnerable         = '¡Vulnerable!' if response['details']['drownVulnerable'] == True else 'No vulnerable'
    vuln_vulnBeast               = '¡Vulnerable!' if response['details']['vulnBeast'] == True else 'No vulnerable'
    vuln_zombiePoodle            = '¡Vulnerable!' if response['details']['zombiePoodle'] == 3 else 'No vulnerable'
    vuln_openSslCcs              = '¡Vulnerable!' if response['details']['openSslCcs'] == 3 else 'No vulnerable'
    vuln_openSSLLuckyMinus20     = '¡Vulnerable!' if response['details']['openSSLLuckyMinus20'] == 2 else 'No vulnerable'
    vuln_ticketbleed             = '¡Vulnerable!' if response['details']['ticketbleed'] == 2 else 'No vulnerable'
    vuln_bleichenbacher          = '¡Vulnerable!' if response['details']['bleichenbacher'] in (2, 3) else 'No vulnerable'
    vuln_goldenDoodle            = '¡Vulnerable!' if response['details']['goldenDoodle'] in (4, 5) else 'No vulnerable'
    vuln_zeroLengthPaddingOracle = '¡Vulnerable!' if response['details']['zeroLengthPaddingOracle'] in (6, 7) else 'No vulnerable'
    vuln_sleepingPoodle          = '¡Vulnerable!' if response['details']['sleepingPoodle'] in (10, 11) else 'No vulnerable'
    vuln_poodleTls               = '¡Vulnerable!' if response['details']['poodleTls'] == 2 else 'No vulnerable'
    vuln_freak                   = '¡Vulnerable!' if response['details']['freak'] == True else 'No vulnerable'

    return {'grade': grade, 'is_exceptional': is_exceptional, 'is_trusted': is_trusted, 'trust_error': trust_error, 'has_sct': has_sct, 'server_signature': server_signature, 'sni_required': sni_required, 'hsts_policy': hsts_policy, 'hpkp_policy': hpkp_policy, 'protocols': protocols, 'vuln_poodle': vuln_poodle, 'vuln_heartbleed': vuln_heartbleed, 'vuln_heartbeat': vuln_heartbeat, 'vuln_freak': vuln_freak, 'vuln_logjam': vuln_logjam, 'vuln_drownVulnerable': vuln_drownVulnerable, 'vuln_vulnBeast': vuln_vulnBeast, 'vuln_zombiePoodle': vuln_zombiePoodle, 'vuln_openSslCcs': vuln_openSslCcs, 'vuln_openSSLLuckyMinus20': vuln_openSSLLuckyMinus20, 'vuln_ticketbleed': vuln_ticketbleed, 'vuln_bleichenbacher': vuln_bleichenbacher, 'vuln_goldenDoodle': vuln_goldenDoodle, 'vuln_zeroLengthPaddingOracle': vuln_zeroLengthPaddingOracle, 'vuln_sleepingPoodle': vuln_sleepingPoodle, 'vuln_poodleTls': vuln_poodleTls, 'vuln_freak': vuln_freak}

def create_txt(host, cert_info, sslabs_result):

    var = '[------------- '+host+' -------------]\n'
    var += '[Sujeto] Dominio: '+cert_info['subject']+'\n'

    if cert_info['subject_org'] != None:
        var += '[Sujeto] Organización: '+cert_info['subject_org']+'\n'

    if cert_info['issuer_organization_name'] != None and cert_info['issuer_organization_unit_name'] != None:
        var += '[Emisor] Organización: '+cert_info['issuer_organization_name']+' ('+cert_info['issuer_organization_unit_name']+')\n'
    
    if cert_info['issuer_organization_name'] != None and cert_info['issuer_organization_unit_name'] == None:
        var += '[Emisor] Organización: '+cert_info['issuer_organization_name']+'\n'

    var += 'No. de serie: '+cert_info['serial']+'\n'
    var += 'Algoritmo de hash: '+cert_info['cert_algo']+'\n'
    var += 'Versión: v'+str(cert_info['cert_version'])+'\n'
    var += 'Inicio de vigencia: '+cert_info['valid_from']+'\n'
    var += 'Fin de vigencia: '+cert_info['valid_to']+'\n'

    if cert_info['cert_expired'] == True:
        var += 'Vigencia: CERTIFICADO VENCIDO\n'
    else:
        var += 'Vigencia: Vigente ('+str(cert_info['remaining_days'])+' días restantes)\n'

    var += 'Dominios asociados:\n'
    for domain in cert_info['cert_domains'].split(', '):
        var += '\t\\_ '+domain+'\n'

    var += '\n[--- Informe de SSLabs ---]\n'

    if sslabs_result['is_exceptional'] == True:
        var += 'CERTIFICADO IMPLEMENTADO CORRECTAMENTE. CALIFICACIÓN EXCEPCIONAL.\n'

    var += 'Calificación: '+sslabs_result['grade']+'\n'

    if sslabs_result['is_trusted'] == False:
        var += 'Confiabilidad: NO confiable\n'

        if 'invalid certificate' in sslabs_result['trust_error']:
            var += '\t\\_ Motivo: Certificado INVÁLIDO\n'

        elif 'certificate revoked' in sslabs_result['trust_error']:
            var += '\t\\_ Motivo: Certificado REVOCADO\n'

        else:
            var += '\t\\_ Motivo: '+sslabs_result['trust_error']+'\n'

    else:
        var += 'Confiabilidad: Confiable\n'

    if sslabs_result['server_signature'] != None:
        var += 'Firma del servidor: '+sslabs_result['server_signature']+'\n'

    var += 'Navegador con soporte SNI requerido: '+sslabs_result['sni_required']+'\n'

    if sslabs_result['has_sct'] == 1:
        var += 'Disponible en Certificate Transparency Logs: Sí\n'
    else:
        var += 'Disponible en Certificate Transparency Logs: NO\n'


    if sslabs_result['hsts_policy'] == 'present':
        var += 'Cabecera HSTS implementada correctamente: Sí\n'
    else:
        var += 'Cabecera HSTS implementada correctamente: NO\n'

    if sslabs_result['hpkp_policy'] == 'present':
        var += 'Cabecera HPKP implementada correctamente: Sí\n'
    else:
        var += 'Cabecera HPKP implementada correctamente: NO\n'

    var += 'Protocolos permitidos:\n'
    for protocol in sslabs_result['protocols']:
        var += '\t\\_ '+protocol['name']+' '+protocol['version']+'\n'

    var += '\n-- Vulnerabilidades --\n'

    var += 'Poodle: '+sslabs_result['vuln_poodle']+'\n'
    var += 'Heartbleed: '+sslabs_result['vuln_heartbleed']+'\n'
    var += 'Heartbeat: '+sslabs_result['vuln_heartbeat']+'\n'
    var += 'Freak: '+sslabs_result['vuln_freak']+'\n'
    var += 'Logjam: '+sslabs_result['vuln_logjam']+'\n'
    var += 'DrownVulnerable: '+sslabs_result['vuln_drownVulnerable']+'\n'
    var += 'VulnBeast: '+sslabs_result['vuln_vulnBeast']+'\n'
    var += 'ZombiePoodle: '+sslabs_result['vuln_zombiePoodle']+'\n'
    var += 'OpenSslCcs: '+sslabs_result['vuln_openSslCcs']+'\n'
    var += 'OpenSSLLuckyMinus20: '+sslabs_result['vuln_openSSLLuckyMinus20']+'\n'
    var += 'Ticketbleed: '+sslabs_result['vuln_ticketbleed']+'\n'
    var += 'Bleichenbacher: '+sslabs_result['vuln_bleichenbacher']+'\n'
    var += 'GoldenDoodle: '+sslabs_result['vuln_goldenDoodle']+'\n'
    var += 'ZeroLengthPaddingOracle: '+sslabs_result['vuln_zeroLengthPaddingOracle']+'\n'
    var += 'SleepingPoodle: '+sslabs_result['vuln_sleepingPoodle']+'\n'
    var += 'PoodleTls: '+sslabs_result['vuln_poodleTls']+'\n'

    print('\tCreando archivo status_'+host+'.txt')

    with open('status_'+host+'.txt', 'w') as f:
        f.write(var)

    return var