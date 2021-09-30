import fire

class Xibalba:

    print('''\n\n
`YMM'   `MP' `7MMF'`7MM"""Yp,       db      `7MMF'      `7MM"""Yp,       db      
  VMb.  ,P     MM    MM    Yb      ;MM:       MM          MM    Yb      ;MM:     
   `MM.M'      MM    MM    dP     ,V^MM.      MM          MM    dP     ,V^MM.    
     MMb       MM    MM"""bg.    ,M  `MM      MM          MM"""bg.    ,M  `MM    
   ,M'`Mb.     MM    MM    `Y    AbmmmqMA     MM      ,   MM    `Y    AbmmmqMA   
  ,P   `MM.    MM    MM    ,9   A'     VML    MM     ,M   MM    ,9   A'     VML  
.MM:.  .:MMa..JMML..JMMmmmd9  .AMA.   .AMMA..JMMmmmmMMM .JMMmmmd9  .AMA.   .AMMA.\n\n''')
    """
    Xibalbá: un framework para la gestión y supervisión de certificados SSL/TLS. Trabajo Fin de Master de Héctor David Victoria Puga.
    """

    def searchsd(self, domain: str):
        """
        Busca el dominio `domain` en Certificate Transparency Logs de Google y regresa dos archivos: results_domain.csv (listado de certificados existentes y dominios/subdominios existentes) y subdomains_domain.csv (Listado de dominios identificados y un resumen de resolución).
        :param domain: Dominio a buscar en Certificate Transparency Logs de Google.
        """
        import src.ctl as ctl

        print('Iniciando búsqueda del dominio:', domain)
        print('Buscando en CTL de Google...')
        results         = ctl.get_transparency_report(domain)
        print('Obteniendo dominios/subdominios asociados...')
        all_domains     = ctl.get_all_targets(results)
        print('Generando reporte general de estatus CTL...')
        ctl.generate_ctl_csv(domain, results)
        print('Generando reporte de resolución de subdominios encontrados...')
        ctl.generate_subdomains_csv(domain, all_domains)
        print('Proceso finalizado. Podrá encontrar los documentos en el directorio de Xibalbá.')


    def verify(self, domain: str):
        """
        Obtiene el certificado expuesto del `domain`, analiza la información del certificado, ejecuta un análisis de seguridad en SSLabs y genera un informe llamado status_domain.txt. De igual forma, toma una instantánea del estado del certificado para poder volver a comparar en el futuro.
        :param domain: Dominio a analizar.
        """
        import src.valdomain as valdomain
        import src.models as models
        import json

        print('Iniciando verificación del dominio:', domain)
        print('Obteniendo el certificado expuesto en el dominio...')
        cert          = valdomain.get_cert(domain)
        print('Leyendo la información del certificado...')
        cert_info     = valdomain.get_cert_info(cert)
        print('Realizando análisis en SSLabs, esta tarea puede tardar unos minutos...')
        sslabs_result = valdomain.check_sslabs(domain)

        models.save_results(domain, cert_info['serial'], json.dumps(cert_info), json.dumps(sslabs_result))

        result        = valdomain.create_txt(domain, cert_info, sslabs_result)

        print('\n\n--------------- RESULTADO DE LA VERIFICACIÓN ---------------\n\n')
        print(result)


        print('Proceso finalizado. Podrá encontrar el documento en el directorio de Xibalbá.')


    def typosint(self, domain: str):
        """
        Recibe un dominio y genera a través de 12 diferentes técnicas de typosquatting un gran parque de dominios, con ellos, realiza un ping a cada uno para identificar si resuelven, y, por último, realiza un reporte con los dominios y el estatus de resolución (typosquatting_domain.csv) junto con un reporte de WHOIS de los dominios activos (whois_typosquatting_domain.txt).
        :param domain: Dominio a analizar.
        """
        import src.typosint as typosint

        print('Iniciando verificación del dominio:', domain)
        print('Generando probables dominios...')
        domains = typosint.fuzz(domain)
        print('Visitando dominios generados, esta tarea puede tardar unos minutos...')
        domains_review = typosint.check(domains)
        print('Generando reporte de resultados...')
        typosint.create_csv(domain, domains_review)
        print('Generando reporte whois...')
        typosint.who_is(domain, domains_review)
        print('Proceso finalizado. Podrá encontrar los documentos en el directorio de Xibalbá.')

    def chkassets(self):
        """
        Ejecuta una nueva verificación sobre los dominios previamente consultados con el comando 'verify' para comparar el estado y cambios en el transcurso del tiempo. De igual forma, genera un reporte de los cambios significativos y alertas de vencimiento y seguridad.
        """
        import pendulum
        import json
        import src.models as models
        import src.valdomain as valdomain
        domains = models.get_domains_list()

        print('Se identificaron {} dominio(s) en el histórico.\n'.format(len(domains)))

        for domain in domains:
            host      = domain[0]
            last_exec = pendulum.from_timestamp(int(domain[1])).to_datetime_string()
            print(host, '- Ultima revisión: '+last_exec)


        print('\n')

        for domain in domains:

            diff = False

            host             = domain[0]
            db_info          = models.get_last_result(host)
            cert_info_db     = json.loads(db_info[3])
            sslabs_result_db = json.loads(db_info[4])

            print('[---------------'+host+'---------------]')
            print('Iniciando verificación del dominio.')
            cert          = valdomain.get_cert(host)
            cert_info     = valdomain.get_cert_info(cert)
            sslabs_result = valdomain.check_sslabs(host)

            if cert_info_db['serial'] != cert_info['serial']:
                diff = True

            if sslabs_result_db != sslabs_result:
                diff = True

            print('Días de vigencia del certificado: '+str(cert_info['remaining_days']))

            if diff == False:
                print(host+': No hay cambios en el certificado ni en la configuración del dominio desde la última ejecución.\n')
            else:
                alert_msg = '''\n
    /   \     |  |     |   ____||   _  \     |           |    /   \     |  | 
   /  ^  \    |  |     |  |__   |  |_)  |    `---|  |----`   /  ^  \    |  | 
  /  /_\  \   |  |     |   __|  |      /         |  |       /  /_\  \   |  | 
 /  _____  \  |  `----.|  |____ |  |\  \----.    |  |      /  _____  \  |__| 
/__/     \__\ |_______||_______|| _| `._____|    |__|     /__/     \__\ (__) \n'''
                print(alert_msg)                                                            
                print('¡ATENCIÓN! - SE IDENTIFICARON DIFERENCIAS EN LA CONFIGURACIÓN ACTUAL VS LA ÚLTIMA CONFIGURACIÓN CONOCIDA.\n')
            
            models.save_results(host, cert_info['serial'], json.dumps(cert_info), json.dumps(sslabs_result))


if __name__ == "__main__":
    fire.Fire(Xibalba)