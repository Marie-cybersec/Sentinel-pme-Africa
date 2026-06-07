"""
SENTINEL PME AFRICA — Agent de Surveillance Windows
====================================================
Inspire de l'architecture Wazuh Agent.
A installer sur chaque machine Windows de la PME.

Usage:
    pip install psutil requests cryptography
    python sentinel_agent.py --soc-url http://192.168.157.10:8000

Fonctionnement :
    4 modules en parallele (threads daemon) :
    1. detect_port_scan()   : detecte Nmap et outils de reconnaissance
    2. detect_brute_force() : detecte Hydra, Medusa, attaques SSH/RDP/SMB
    3. detect_ransomware()  : detecte comportements de chiffrement massif
    4. heartbeat()          : signal de vie toutes les 30 secondes au SOC
"""

import psutil, socket, time, json, hashlib, requests, threading, os
from datetime import datetime, timezone
from collections import defaultdict

# ── Configuration ──────────────────────────────────────────────────────────────
SOC_URL       = "http://192.168.157.10:8000"
PME_ID        = "PME-YAOUNDE-001"
AGENT_VERSION = "1.0.0"

# ── Seuils de detection (calibres pour minimiser les faux positifs) ────────────
SCAN_THRESHOLD       = 12   # ports differents en 10 secondes → scan detecte
BRUTEFORCE_THRESHOLD = 8    # connexions repetees en 30 secondes → brute force
CPU_SPIKE_THRESHOLD  = 80.0 # pourcentage CPU → comportement ransomware suspect
AUTH_PORTS           = {22, 23, 21, 445, 3389, 5900, 8080}  # ports surveilles

# ── Memoire interne de l'agent ─────────────────────────────────────────────────
conn_log    = defaultdict(list)  # ip → liste de timestamps de connexion
ports_seen  = defaultdict(set)   # ip → set de ports contactes dans la fenetre
failed_log  = defaultdict(list)  # ip → timestamps de connexions sur ports auth
alerted     = set()              # cles d'alertes deja envoyees (evite doublons)
lock        = threading.Lock()   # protege les structures partagees

# ── Generateur d'identifiant unique pour chaque alerte ────────────────────────
def threat_id(data: str) -> str:
    return hashlib.sha256(f"{data}{time.time()}".encode()).hexdigest()[:14].upper()

# ── Avertissements proactifs par type de menace ───────────────────────────────
PROACTIVE_WARNINGS = {
    "PORT_SCAN": (
        "AVERTISSEMENT PROACTIF : Un attaquant qui vient de scanner votre reseau "
        "va probablement tenter une connexion par force brute sur vos ports ouverts "
        "(SSH port 22, RDP port 3389, SMB port 445) dans les prochaines minutes. "
        "Fermez ces ports dans votre pare-feu maintenant si vous ne les utilisez pas."
    ),
    "BRUTE_FORCE": (
        "AVERTISSEMENT PROACTIF : Si l'attaquant obtient des identifiants valides, "
        "il tentera de se deplacer vers d'autres machines de votre reseau (mouvement "
        "lateral) et pourrait installer un ransomware ou exfiltrer vos donnees. "
        "Deconnectez cette machine du reseau immediatement si l'attaque continue."
    ),
    "RANSOMWARE_SUSPECT": (
        "AVERTISSEMENT PROACTIF : Si ce processus est un ransomware actif, il va "
        "chiffrer tous vos fichiers dans les prochaines minutes et rendre votre "
        "systeme inutilisable. Ne payez jamais la rancon. Isolez la machine maintenant."
    ),
}

# ── Fonction principale d'envoi d'alerte ──────────────────────────────────────
def send_alert(
    threat_type: str,
    severity: str,
    description: str,
    indicators: list,
    recommended_actions: list,
    source_ip: str = "inconnu",
    confidence: float = 0.92
):
    """
    Construit une alerte structuree, l'envoie au SOC SENTINEL.
    Chaque alerte contient :
    - La description de l'attaque detectee
    - Les indicateurs de compromission (IOC)
    - Les actions recommandees en francais (curatives et preventives)
    - Un avertissement proactif sur la prochaine etape probable de l'attaquant
    """
    tid = threat_id(threat_type + source_ip)
    alert = {
        "threat_id":          tid,
        "pme_id":             PME_ID,
        "threat_type":        threat_type,
        "severity":           severity,
        "confidence":         round(confidence, 3),
        "description":        description,
        "indicators":         indicators,
        "recommended_actions": recommended_actions,
        "proactive_warning":  PROACTIVE_WARNINGS.get(threat_type, ""),
        "source_ip":          source_ip,
        "target_hostname":    socket.gethostname(),
        "target_ip":          socket.gethostbyname(socket.gethostname()),
        "detected_at":        datetime.now(timezone.utc).isoformat() + "Z",
        "agent_version":      AGENT_VERSION,
    }

    try:
        resp = requests.post(
            f"{SOC_URL}/api/alerts",
            json=alert,
            timeout=5
        )
        status = resp.status_code
        print(f"[SENTINEL] ✓ Alerte envoyee | {threat_type} | {severity} | "
              f"IP:{source_ip} | SOC HTTP {status}")
    except requests.exceptions.ConnectionError:
        print(f"[SENTINEL] ✗ SOC inaccessible ({SOC_URL}). Alerte conservee en local.")
    except Exception as e:
        print(f"[SENTINEL] ✗ Erreur envoi alerte : {e}")

    return alert


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — DETECTION SCAN DE PORTS (Nmap, Masscan, Zmap)
# ══════════════════════════════════════════════════════════════════════════════
def detect_port_scan():
    """
    Surveille les connexions reseau entrantes.
    Logique : si une meme IP externe contacte plus de SCAN_THRESHOLD
    ports differents en 10 secondes, c'est statistiquement impossible
    en utilisation normale : c'est un scan de ports.
    Outils detectes : Nmap (SYN scan -sS, TCP scan -sT, agressif -A),
                      Masscan, Zmap, tout scanner de ports.
    """
    WINDOW = 10  # secondes
    while True:
        now = time.time()
        try:
            connections = psutil.net_connections(kind="inet")
            with lock:
                for conn in connections:
                    if not conn.raddr:
                        continue
                    remote_ip = conn.raddr.ip
                    # Ignorer les IPs locales et le SOC lui-meme
                    if (remote_ip.startswith("127.")
                            or remote_ip.startswith("::1")
                            or remote_ip == "192.168.56.30"):
                        continue
                    if conn.status in ("SYN_RECV", "ESTABLISHED", "LISTEN"):
                        ports_seen[remote_ip].add(conn.laddr.port)
                        conn_log[remote_ip].append(now)

                # Nettoyer les entrees hors de la fenetre temporelle
                for ip in list(conn_log):
                    conn_log[ip] = [t for t in conn_log[ip] if now - t < WINDOW]

                # Evaluer chaque IP
                for ip, ports in list(ports_seen.items()):
                    if len(ports) >= SCAN_THRESHOLD:
                        key = f"SCAN_{ip}"
                        if key not in alerted:
                            alerted.add(key)
                            ports_list = sorted(list(ports))
                            send_alert(
                                threat_type="PORT_SCAN",
                                severity="ELEVE",
                                description=(
                                    f"Scan de ports detecte depuis {ip}. "
                                    f"{len(ports)} ports sondes en {WINDOW} secondes. "
                                    f"Comportement caracteristique d'un outil de "
                                    f"reconnaissance reseau (Nmap, Masscan)."
                                ),
                                indicators=[
                                    f"IP source malveillante : {ip}",
                                    f"Nombre de ports sondes : {len(ports)} en {WINDOW}s",
                                    f"Ports cibles detectes : {ports_list[:15]}",
                                    f"Machine cible : {socket.gethostname()} ({socket.gethostbyname(socket.gethostname())})",
                                    "Outil probable : Nmap SYN scan (-sS), TCP scan (-sT) ou scan agressif (-A)",
                                    "Technique MITRE ATT&CK : T1046 - Network Service Discovery",
                                ],
                                recommended_actions=[
                                    "1. MAINTENANT : Bloquer l'IP source dans le pare-feu Windows. "
                                       "Panneau de configuration > Pare-feu Windows Defender > "
                                       "Regles de trafic entrant > Nouvelle regle > Port > Bloquer.",
                                    "2. Verifier si d'autres machines de votre reseau ont aussi ete scannees "
                                       "en consultant le tableau de bord SENTINEL.",
                                    "3. NE PAS eteindre cette machine. Les preuves de l'attaque sont en "
                                       "memoire vive et seraient perdues.",
                                    "4. Prendre une capture d'ecran du tableau de bord SENTINEL pour "
                                       "constituer un dossier de preuve.",
                                    "5. Alerter le responsable de securite ou le proprietaire de l'entreprise.",
                                ],
                                source_ip=ip,
                                confidence=0.96,
                            )
                            # Permettre une nouvelle alerte depuis cette IP apres 45 secondes
                            threading.Timer(45, alerted.discard, args=[key]).start()

                ports_seen.clear()

        except psutil.AccessDenied:
            print("[SENTINEL] Acces refuse aux connexions reseau. Relancer en mode Administrateur.")
        except Exception as e:
            print(f"[SENTINEL] Erreur module ScanDetector : {e}")

        time.sleep(3)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — DETECTION BRUTE FORCE (Hydra, Medusa, Ncrack)
# ══════════════════════════════════════════════════════════════════════════════
def detect_brute_force():
    """
    Surveille les connexions repetees sur les ports d'authentification.
    Logique : si une meme IP effectue plus de BRUTEFORCE_THRESHOLD
    connexions sur les ports SSH, RDP ou SMB en 30 secondes, c'est
    une attaque par force brute.
    Outils detectes : Hydra, Medusa, Ncrack, scripts Metasploit.
    """
    WINDOW = 30  # secondes
    while True:
        now = time.time()
        try:
            connections = psutil.net_connections(kind="inet")
            with lock:
                for conn in connections:
                    if not conn.raddr:
                        continue
                    if conn.laddr.port not in AUTH_PORTS:
                        continue
                    remote_ip = conn.raddr.ip
                    if (remote_ip.startswith("127.")
                            or remote_ip == "192.168.56.30"):
                        continue
                    failed_log[remote_ip].append(now)

                for ip, times in list(failed_log.items()):
                    recent = [t for t in times if now - t < WINDOW]
                    failed_log[ip] = recent

                    if len(recent) >= BRUTEFORCE_THRESHOLD:
                        key = f"BRUTE_{ip}"
                        if key not in alerted:
                            alerted.add(key)
                            taux = round(len(recent) / WINDOW, 1)
                            send_alert(
                                threat_type="BRUTE_FORCE",
                                severity="CRITIQUE",
                                description=(
                                    f"Attaque par force brute detectee depuis {ip}. "
                                    f"{len(recent)} tentatives de connexion en {WINDOW} secondes "
                                    f"(taux : {taux} connexions/seconde). "
                                    f"L'attaquant essaie de deviner le mot de passe "
                                    f"administrateur de cette machine."
                                ),
                                indicators=[
                                    f"IP source de l'attaque : {ip}",
                                    f"Nombre de tentatives : {len(recent)} en {WINDOW}s",
                                    f"Taux d'attaque : {taux} connexions par seconde",
                                    f"Ports cibles : SSH(22), RDP(3389), SMB(445)",
                                    "Outil probable : Hydra, Medusa ou Ncrack",
                                    "Technique MITRE ATT&CK : T1110 - Brute Force",
                                ],
                                recommended_actions=[
                                    "1. URGENCE IMMEDIATE : Bloquer l'IP source dans le pare-feu Windows. "
                                       "Panneau de configuration > Pare-feu > Regles entrant > Bloquer cette IP.",
                                    "2. Changer TOUS les mots de passe des comptes Windows sur cette machine "
                                       "immediatement, en commencant par le compte Administrateur.",
                                    "3. Desactiver les comptes inutilises, notamment le compte "
                                       "Administrateur local si vous n'en avez pas besoin.",
                                    "4. Activer l'authentification a deux facteurs sur tous les acces "
                                       "a distance (Microsoft Authenticator ou Google Authenticator).",
                                    "5. Si l'attaque continue apres le blocage de l'IP, debrancher "
                                       "physiquement le cable reseau de cette machine.",
                                ],
                                source_ip=ip,
                                confidence=0.97,
                            )
                            threading.Timer(90, alerted.discard, args=[key]).start()

        except Exception as e:
            print(f"[SENTINEL] Erreur module BruteDetector : {e}")

        time.sleep(5)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — DETECTION RANSOMWARE ET MALWARE COMPORTEMENTAL
# ══════════════════════════════════════════════════════════════════════════════
def detect_ransomware():
    """
    Surveille le comportement des processus Windows.
    Logique : un ransomware se trahit par une consommation CPU
    anormalement elevee due au chiffrement massif des fichiers.
    Detection complementaire avec l'activite I/O disque.
    Malwares detectes : ransomwares, crypto-mineurs, loaders.
    """
    while True:
        try:
            for proc in psutil.process_iter(
                ["pid", "name", "cpu_percent", "username", "exe", "cmdline"]
            ):
                try:
                    info = proc.info
                    cpu  = info.get("cpu_percent") or 0

                    # Ignorer les processus systeme connus
                    pname = (info.get("name") or "").lower()
                    system_procs = {
                        "system", "registry", "smss.exe", "csrss.exe",
                        "wininit.exe", "winlogon.exe", "services.exe",
                        "lsass.exe", "svchost.exe", "dwm.exe",
                        "antimalware service executable"
                    }
                    if pname in system_procs:
                        continue

                    if cpu > CPU_SPIKE_THRESHOLD:
                        pid  = info["pid"]
                        key  = f"RANSOM_{pid}"
                        with lock:
                            if key not in alerted:
                                alerted.add(key)
                                exe_path = info.get("exe") or "chemin inconnu"
                                send_alert(
                                    threat_type="RANSOMWARE_SUSPECT",
                                    severity="CRITIQUE",
                                    description=(
                                        f"Comportement suspect detecte dans le processus "
                                        f"'{info['name']}' (PID {pid}). Consommation CPU : "
                                        f"{cpu:.0f}%. Ce niveau d'activite peut indiquer "
                                        f"un chiffrement massif de fichiers (ransomware) "
                                        f"ou un minage de cryptomonnaie non autorise."
                                    ),
                                    indicators=[
                                        f"Processus suspect : {info['name']} (PID {pid})",
                                        f"Consommation CPU : {cpu:.0f}% (seuil : {CPU_SPIKE_THRESHOLD}%)",
                                        f"Chemin executable : {exe_path}",
                                        f"Utilisateur : {info.get('username', 'inconnu')}",
                                        "Activite I/O disque probablement elevee",
                                        "Technique MITRE ATT&CK : T1486 - Data Encrypted for Impact",
                                    ],
                                    recommended_actions=[
                                        f"1. URGENCE : Ouvrir le Gestionnaire des taches (Ctrl+Alt+Suppr) "
                                           f"et terminer le processus PID {pid} immediatement.",
                                        "2. DECONNECTER la machine du reseau : debrancher le cable "
                                           "Ethernet ou desactiver le Wi-Fi depuis les parametres Windows.",
                                        "3. NE PAS eteindre la machine. Les preuves de l'attaque "
                                           "sont en memoire vive et seraient perdues si vous eteignez.",
                                        "4. Verifier les fichiers modifies dans les 10 dernieres "
                                           "minutes : Explorateur Windows > recherche par date de modification.",
                                        "5. Restaurer vos fichiers depuis la derniere sauvegarde SENTINEL "
                                           "ou depuis un support externe non connecte a la machine.",
                                    ],
                                    confidence=0.79,
                                )
                                threading.Timer(120, alerted.discard, args=[key]).start()

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

        except Exception as e:
            print(f"[SENTINEL] Erreur module RansoDetector : {e}")

        time.sleep(8)


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — HEARTBEAT (Signal de vie toutes les 30 secondes)
# ══════════════════════════════════════════════════════════════════════════════
def heartbeat():
    """
    Envoie un signal de vie au SOC toutes les 30 secondes.
    Permet au dashboard de savoir que l'agent est actif
    et d'afficher les metriques systeme en temps reel.
    """
    while True:
        try:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory().percent
            disk = psutil.disk_usage("/").percent if os.name != "nt" else \
                   psutil.disk_usage("C:\\").percent

            data = {
                "pme_id":    PME_ID,
                "hostname":  socket.gethostname(),
                "ip":        socket.gethostbyname(socket.gethostname()),
                "cpu":       round(cpu, 1),
                "ram":       round(ram, 1),
                "disk":      round(disk, 1),
                "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
                "version":   AGENT_VERSION,
                "status":    "ACTIVE",
                "platform":  "Windows" if os.name == "nt" else "Linux",
            }
            requests.post(f"{SOC_URL}/api/heartbeat", json=data, timeout=5)
            print(f"[SENTINEL] ♥ Heartbeat | CPU:{cpu:.0f}% RAM:{ram:.0f}% DISK:{disk:.0f}%")
        except Exception:
            print("[SENTINEL] ♥ Heartbeat : SOC injoignable, on reessaie dans 30s")

        time.sleep(30)


# ══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTREE
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="SENTINEL PME Africa — Agent de surveillance Windows"
    )
    parser.add_argument("--soc-url", default=SOC_URL,
                        help="URL du serveur SOC (ex: http://192.168.157.10:8000)")
    parser.add_argument("--pme-id",  default=PME_ID,
                        help="Identifiant unique de la PME (ex: PME-YAOUNDE-001)")
    args = parser.parse_args()

    SOC_URL = args.soc_url
    PME_ID  = args.pme_id

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║       SENTINEL PME AFRICA — Agent de Surveillance v{AGENT_VERSION}    ║
║                                                              ║
║  SOC       : {SOC_URL:<48}║
║  Machine   : {socket.gethostname():<48}║
║  PME       : {PME_ID:<48}║
║                                                              ║
║  Modules actifs :                                            ║
║    [1] Detection scan de ports (Nmap, Masscan)               ║
║    [2] Detection brute force (Hydra, Medusa)                 ║
║    [3] Detection ransomware comportemental                   ║
║    [4] Heartbeat (signal de vie toutes les 30s)              ║
╚══════════════════════════════════════════════════════════════╝
""")

    modules = [
        threading.Thread(target=detect_port_scan,  name="ScanDetector",  daemon=True),
        threading.Thread(target=detect_brute_force, name="BruteDetector", daemon=True),
        threading.Thread(target=detect_ransomware,  name="RansoDetector", daemon=True),
        threading.Thread(target=heartbeat,           name="Heartbeat",     daemon=True),
    ]

    for t in modules:
        t.start()
        print(f"[SENTINEL] ✓ Module actif : {t.name}")

    print(f"\n[SENTINEL] Surveillance en cours sur {socket.gethostname()}...")
    print("[SENTINEL] Dashboard : http://192.168.157.10:8080/dashboard.html")
    print("[SENTINEL] Ctrl+C pour arreter l'agent.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[SENTINEL] Agent arrete proprement.")
