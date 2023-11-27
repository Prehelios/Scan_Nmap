# Scan using Nmap for port and system
# Using scan you can use Metasploit with results
import nmap

def nmap_scan(target):
    # Créer un objet Nmap
    nm = nmap.PortScanner()

    # Effectuer le scan Nmap sur le target
    nm.scan(target, arguments='-p-')

    # Récupérer les résultats
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)

    return open_ports

def service_info(target, port):
    # Effectuer un second scan pour obtenir des informations sur le service et le système
    nm = nmap.PortScanner()
    nm.scan(target, arguments=f'-p {port} --script=banner,info,vuln')

    # Récupérer les informations
    info = {}
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            if nm[host][proto][port]['state'] == 'open':
                info['service'] = nm[host][proto][port]['name']
                info['version'] = nm[host][proto][port]['version']
                info['os'] = nm[host]['osmatch'][0]['name']

    return info

def write_to_file(target, results):
    # Écrire les résultats dans un fichier
    with open(f"scan_results_{target}.txt", 'w') as file:
        file.write("Résultats du scan :\n\n")
        for port, info in results.items():
            file.write(f"Port {port}:\n")
            file.write(f"- Service : {info['service']}\n")
            file.write(f"- Version : {info['version']}\n")
            file.write(f"- Système d'exploitation : {info['os']}\n\n")

def main():
    print("╔════════════════════════════════════════╗")
    print("║             Prehelios Scan                    ║")
    print("╚════════════════════════════════════════╝")

    # Demander à l'utilisateur le site ou l'adresse IP à scanner
    target = input("\nEntrez le site ou l'adresse IP à scanner : ")

    # Effectuer le scan initial pour obtenir les ports ouverts
    open_ports = nmap_scan(target)

    # Pour chaque port ouvert, obtenir des informations sur le service et le système
    results = {}
    for port in open_ports:
        info = service_info(target, port)
        results[port] = info

    # Afficher les résultats
    print("\nRésultats du scan :")
    for port, info in results.items():
        print(f"\nInformations détaillées pour le port {port}:")
        print(f"- Service : {info['service']}")
        print(f"- Version : {info['version']}")
        print(f"- Système d'exploitation : {info['os']}")

    # Écrire les résultats dans un fichier
    write_to_file(target, results)
    print("\nLes résultats ont été enregistrés dans un fichier lisible par Metasploit.")

if __name__ == "__main__":
    main()
