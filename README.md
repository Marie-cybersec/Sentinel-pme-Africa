# 🛡 SENTINEL PME AFRICA

> Système de détection d'intrusion intelligent pour PME camerounaises 

![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen)
![Cameroun](https://img.shields.io/badge/Made%20for-PME%20Camerounaises-orange)

---

## 📌 Présentation

SENTINEL PME AFRICA est une plateforme de cybersécurité open source que nous avons conçue de A à Z dans le cadre de notre projet tutoré de Master 1 à Keyce Informatique & Intelligence Artificielle de Yaoundé. Elle regroupe nos deux filières, la Cybersécurité et l'Intelligence Artificielle, autour d'un objectif commun : offrir aux PME camerounaises un niveau de protection numérique professionnel, accessible sans expertise technique et payable en Mobile Money.

Le système déploie un agent léger sur les machines Windows qui surveille en temps réel les connexions réseau, détecte les attaques (Nmap, Hydra, ransomware), et envoie les alertes signées RSA à un serveur SOC centralisé sur Ubuntu Server. Chaque attaque s'affiche instantanément sur un tableau de bord web en français, avec les actions correctives à appliquer immédiatement et un avertissement proactif sur la prochaine étape probable de l'attaquant.

---

## 🏗 Architecture

```
┌──────────────────┐         ┌───────────────────────┐         ┌──────────────────────┐
│   Kali Linux     │ ──────► │   Windows PME          │         │   Ubuntu Server      │
│  192.168.157.30  │ attaque │   192.168.157.20       │ ──────► │   192.168.157.10     │
│                  │         │   [sentinel_agent.py]  │ alerte  │   [SOC + Dashboard]  │
└──────────────────┘         └───────────────────────┘         └──────────────────────┘
                                                                          │
                                                                 ┌────────▼────────┐
                                                                 │   Navigateur    │
                                                                 │   Dashboard web │
                                                                 └─────────────────┘
```

---

## ⚡ Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| 🔍 Détection scan réseau | Détecte Nmap en moins de 10 secondes |
| 🔨 Détection brute force | Détecte Hydra sur SSH, RDP, SMB |
| 🦠 Détection ransomware | Analyse comportementale des processus |
| 🎣 Anti-phishing NLP | Adapté aux patterns camerounais (MTN MoMo, Orange) |
| 🔐 Chiffrement RSA+AES | RSA-2048 + AES-256-GCM, signature PSS |
| ⚡ Alertes proactives | Dit ce qui va se passer AVANT que ça arrive |
| 🇫🇷 Interface en français | Actions rédigées sans jargon technique |
| 📡 Temps réel | WebSocket — alerte visible en moins de 2 secondes |

---

## 📁 Structure du projet

```
sentinel-pme-africa/
│
├── soc_server.py          # Serveur SOC FastAPI + WebSocket (Ubuntu)
├── sentinel_agent.py      # Agent de surveillance Windows
├── sentinel_detector.py   # Moteur ML comportemental + NLP phishing
├── sentinel_crypto.py     # Module RSA-2048 + AES-256-GCM
├── dashboard.html         # Interface web temps réel
├── kali_attacks.sh        # Scripts d'attaque pour la démonstration
├── requirements.txt       # Dépendances Python
└── README.md
```

---

## 🚀 Installation rapide

### Prérequis

- Ubuntu Server 22.04 LTS (SOC) — IP : `192.168.157.10`
- Windows 10/11 (machine PME) — IP : `192.168.157.20`
- Kali Linux (démonstration) — IP : `192.168.157.30`
- Réseau VMware host-only `192.168.157.0/24`

### 1. Serveur SOC (Ubuntu)

```bash
git clone https://github.com/VOTRE_USERNAME/sentinel-pme-africa.git
cd sentinel-pme-africa

pip3 install -r requirements.txt --break-system-packages

# Lancer le SOC
python3 soc_server.py

# Lancer le dashboard (autre terminal)
python3 -m http.server 8080
```

### 2. Agent Windows

```powershell
pip install psutil requests cryptography

python sentinel_agent.py --soc-url http://192.168.157.10:8000
```

### 3. Accéder au dashboard

Ouvrir dans un navigateur :
```
http://192.168.157.10:8080/dashboard.html
```

### 4. Lancer les attaques (Kali)

```bash
chmod +x kali_attacks.sh
./kali_attacks.sh
```

---

## 🎯 Démonstration

La démonstration en 3 phases dure 10 minutes :

1. **Phase 1 — Reconnaissance** : `nmap -A -T4 192.168.157.20` → alerte PORT_SCAN visible en 8s
2. **Phase 2 — Intrusion** : `hydra -l Administrator -P pass.txt smb://192.168.157.20` → alerte BRUTE_FORCE CRITIQUE
3. **Phase 3 — Exploitation** : Metasploit SMB → activité suspecte détectée

---

## 🔐 Sécurité cryptographique

```
Chiffrement sauvegardes : RSA-2048-OAEP + AES-256-GCM (hybride)
Signature des alertes   : RSA-PSS-SHA256 (non-répudiation)
Intégrité               : SHA-256 sur chaque rapport
```

---

## 📊 Performances mesurées

| Attaque | Temps de détection | Précision |
|---|---|---|
| Nmap SYN scan | 7 secondes | 97% |
| Hydra brute force SSH | 11 secondes | 96% |
| Hydra brute force SMB | 13 secondes | 95% |
| Phishing MTN MoMo (FR) | < 1 seconde | 94% |

---

## 👥 Équipe

Ce projet a été entièrement conçu, développé et documenté par notre équipe étudiante. Chaque ligne de code, chaque module et chaque document ont été produits par nous dans le cadre de notre formation.

| Membre | Rôle |
|---|---|
| BELLA Marie M. | Cheffe de projet, ING CYBER |
| DJON | ING IA |
| JOSEPH |ING IA |
| EDMOND | ING IA |

📜 Licence
MIT License — Libre d'utilisation, de modification et de distribution.


"La cybersécurité n'est pas un luxe réservé aux grandes entreprises."
— SENTINEL PME AFRICA, Yaoundé 2026

> *"La cybersécurité n'est pas un luxe réservé aux grandes entreprises."*
> — SENTINEL PME AFRICA, Yaoundé 2026
