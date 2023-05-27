import nmap

# Crear un objeto nmap.PortScanner()
nm = nmap.PortScanner()

# Especificar el objetivo y los argumentos para Nmap
target_host = input("Ingrese la dirección IP del objetivo: ")
nm.scan(hosts=target_host, arguments='-sV')

# Diccionario de vulnerabilidades
vulnerabilidades = {
    'http-vuln-cve2014-6271.nse': 'CVE-2014-6271 (Shellshock)',
    'http-vuln-cve2017-5638.nse': 'CVE-2017-5638 (Apache Struts2 S2-045)',
    'smb-vuln-ms17-010.nse': 'MS17-010 (EternalBlue)',
    'smtp-vuln-cve2010-4344.nse': 'CVE-2010-4344 (Exim string_format)',
    'dns-zone-transfer.nse': 'DNS zone transfer',
    'http-robots.txt.nse': 'robots.txt disclosure',
    'http-vuln-cve2015-1635.nse': 'CVE-2015-1635 (IIS HTTP.sys)',
    'http-vuln-cve2017-1001000.nse': 'CVE-2017-1001000 (Jenkins)',
    'http-vuln-cve2017-7494.nse': 'CVE-2017-7494 (SambaCry)',
    'ssl-heartbleed.nse': 'Heartbleed (CVE-2014-0160)'
}

# Iterar a través de los puertos y servicios descubiertos
for host in nm.all_hosts():
    print(f"El host {host} está {nm[host].state()}")
    for proto in nm[host].all_protocols():
        print(f"Protocolo : {proto}")
        lport = nm[host][proto].keys()
        for port in lport:
            print(f"Puerto: {port} \tEstado: {nm[host][proto][port]['state']}")

            # Detectar posibles vulnerabilidades utilizando Nmap NSE
            for script_name in vulnerabilidades:
                if 'script' in nm[host][proto][port] and script_name in nm[host][proto][port]['script']:
                    print(f"El servidor {host} podría ser vulnerable a {vulnerabilidades[script_name]} ({script_name})")
