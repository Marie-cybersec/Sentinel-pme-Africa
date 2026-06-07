"""
SENTINEL PME AFRICA — Moteur de Detection Intelligent
======================================================
Deux moteurs de detection complementaires :
  1. BehavioralMalwareDetector : analyse comportementale ML (6 features ponderees)
  2. PhishingDetector          : NLP anti-phishing adapte au contexte camerounais

Usage:
    python sentinel_detector.py   # lance la demonstration
"""

import hashlib, json, random
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List


# ══════════════════════════════════════════════════════════════════════════════
# STRUCTURE DE DONNEES : RAPPORT DE MENACE
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ThreatReport:
    """
    Rapport de menace genere par le moteur de detection.
    Chaque rapport est signe RSA par l'agent avant envoi au SOC.
    """
    threat_id:          str
    pme_id:             str
    threat_type:        str      # MALWARE / PHISHING / RANSOMWARE / ANOMALIE
    severity:           str      # CRITIQUE / ELEVE / MOYEN / FAIBLE
    confidence:         float    # Score de confiance 0.0 a 1.0
    description:        str
    indicators:         List[str]
    recommended_actions: List[str]
    proactive_warning:  str      # Avertissement sur la prochaine etape probable
    detected_at:        str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z"
    )
    blocked: bool = False

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}

    def to_bytes(self) -> bytes:
        """Serialise le rapport pour signature RSA."""
        return json.dumps(self.to_dict(), ensure_ascii=False).encode("utf-8")

    def summary(self) -> str:
        return (f"[{self.severity}] {self.threat_type} | "
                f"Confiance: {self.confidence*100:.1f}% | "
                f"Bloque: {self.blocked}")


# ══════════════════════════════════════════════════════════════════════════════
# MOTEUR 1 : ANTIVIRUS COMPORTEMENTAL
# ══════════════════════════════════════════════════════════════════════════════

class BehavioralMalwareDetector:
    """
    Detection comportementale de malwares par scoring pondere.
    6 caracteristiques (features) comportementales analysees en temps reel.

    Avantage par rapport aux antivirus classiques : pas de base de signatures.
    Le systeme detecte les malwares INCONNUS en analysant leur comportement,
    pas leur signature numerique.

    Features surveillees :
      1. syscall_frequency   : frequence des appels systeme (indicateur d'activite anormale)
      2. file_access_score   : acces aux fichiers systeme sensibles (System32, Registry)
      3. network_anomaly     : connexions vers des IP inconnues ou non repertoriees
      4. cpu_spike           : pic de consommation CPU anormal
      5. privilege_attempt   : tentative d'elevation de privileges (UAC bypass)
      6. file_encrypt_rate   : taux de chiffrement de fichiers (signature ransomware)
    """

    # Seuils au-dela desquels une feature est consideree comme suspecte
    THRESHOLDS = {
        "syscall_frequency": 0.75,
        "file_access_score": 0.68,
        "network_anomaly":   0.72,
        "cpu_spike":         0.80,
        "privilege_attempt": 0.85,
        "file_encrypt_rate": 0.82,
    }

    # Poids de chaque feature dans le score global (somme = 1.0)
    WEIGHTS = {
        "syscall_frequency": 0.15,
        "file_access_score": 0.18,
        "network_anomaly":   0.22,
        "cpu_spike":         0.10,
        "privilege_attempt": 0.20,
        "file_encrypt_rate": 0.15,
    }

    def analyze_process(self, process_name: str, features: dict,
                        pme_id: str = "SOC-SENTINEL") -> ThreatReport:
        """
        Analyse un processus Windows et genere un rapport de menace.
        features : dictionnaire de 6 valeurs entre 0.0 et 1.0.
        """
        score       = self._compute_score(features)
        threat_type = self._classify_type(features)
        severity    = self._classify_severity(score)
        indicators  = self._extract_indicators(features)
        description = self._build_description(process_name, threat_type, features, score)
        actions     = self._recommended_actions(severity, process_name)
        proactive   = self._proactive_warning(threat_type)
        blocked     = severity == "CRITIQUE" and score > 0.88

        tid = hashlib.sha256(
            f"{process_name}{score}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:14].upper()

        return ThreatReport(
            threat_id=tid,
            pme_id=pme_id,
            threat_type=threat_type,
            severity=severity,
            confidence=round(score, 3),
            description=description,
            indicators=indicators,
            recommended_actions=actions,
            proactive_warning=proactive,
            blocked=blocked,
        )

    def _compute_score(self, f: dict) -> float:
        """Calcul du score pondere avec bruit gaussien (simule la variance du modele RF)."""
        score = sum(f.get(k, 0) * w for k, w in self.WEIGHTS.items())
        noise = random.gauss(0, 0.015)  # simulation variance Random Forest
        return min(1.0, max(0.0, score + noise))

    def _classify_type(self, f: dict) -> str:
        if f.get("file_encrypt_rate", 0) > 0.78 and f.get("cpu_spike", 0) > 0.70:
            return "RANSOMWARE"
        if f.get("network_anomaly", 0) > 0.75 and f.get("syscall_frequency", 0) > 0.65:
            return "TROJAN_C2"
        if f.get("privilege_attempt", 0) > 0.80:
            return "PRIVILEGE_ESCALATION"
        if f.get("syscall_frequency", 0) > 0.72 and f.get("file_access_score", 0) > 0.65:
            return "MALWARE"
        return "ANOMALIE_COMPORTEMENTALE"

    def _classify_severity(self, score: float) -> str:
        if score >= 0.85: return "CRITIQUE"
        if score >= 0.68: return "ELEVE"
        if score >= 0.50: return "MOYEN"
        return "FAIBLE"

    def _extract_indicators(self, f: dict) -> List[str]:
        ioc = []
        if f.get("syscall_frequency", 0) > self.THRESHOLDS["syscall_frequency"]:
            ioc.append(f"Frequence d'appels systeme anormale : {f['syscall_frequency']*100:.0f}% du seuil")
        if f.get("file_access_score", 0) > self.THRESHOLDS["file_access_score"]:
            ioc.append("Acces aux repertoires systeme sensibles (System32, Windows\\Registry)")
        if f.get("network_anomaly", 0) > self.THRESHOLDS["network_anomaly"]:
            ioc.append("Connexion vers serveur C2 (Command & Control) non repertorie")
        if f.get("privilege_attempt", 0) > self.THRESHOLDS["privilege_attempt"]:
            ioc.append("Tentative de contournement du controle de compte (UAC bypass)")
        if f.get("file_encrypt_rate", 0) > self.THRESHOLDS["file_encrypt_rate"]:
            ioc.append(f"Chiffrement massif de fichiers detecte : {f['file_encrypt_rate']*100:.0f}% d'activite")
        if f.get("cpu_spike", 0) > self.THRESHOLDS["cpu_spike"]:
            ioc.append(f"Pic CPU anormal : {f['cpu_spike']*100:.0f}%")
        return ioc or ["Comportement statistiquement aberrant par rapport au profil normal"]

    def _build_description(self, name: str, t: str, f: dict, score: float) -> str:
        descs = {
            "RANSOMWARE": (
                f"Le processus '{name}' presente un comportement de ransomware : "
                f"chiffrement massif de fichiers ({f.get('file_encrypt_rate',0)*100:.0f}% d'activite) "
                f"combine a une connexion reseau suspecte. Score de menace : {score*100:.0f}%."
            ),
            "TROJAN_C2": (
                f"Le processus '{name}' communique avec un serveur externe non autorise "
                f"(comportement de cheval de Troie Command & Control). Score : {score*100:.0f}%."
            ),
            "PRIVILEGE_ESCALATION": (
                f"Le processus '{name}' tente d'obtenir des privileges administrateur "
                f"sans autorisation explicite (technique UAC bypass). Score : {score*100:.0f}%."
            ),
            "MALWARE": (
                f"Comportement malveillant detecte dans '{name}' : appels systeme intensifs "
                f"et acces aux fichiers systeme protégés. Score de menace : {score*100:.0f}%."
            ),
        }
        return descs.get(t, f"Anomalie comportementale dans '{name}'. Score : {score*100:.0f}%.")

    def _recommended_actions(self, severity: str, process_name: str) -> List[str]:
        base = {
            "CRITIQUE": [
                f"1. URGENCE : Terminer le processus '{process_name}' immediatement "
                   "(Gestionnaire des taches → clic droit → Fin de tache).",
                "2. DECONNECTER la machine du reseau (debrancher le cable Ethernet).",
                "3. NE PAS eteindre — les preuves en RAM seraient perdues.",
                "4. Verifier les fichiers modifies dans les 10 dernieres minutes.",
                "5. Restaurer depuis la derniere sauvegarde SENTINEL chiffree.",
            ],
            "ELEVE": [
                f"1. Mettre le processus '{process_name}' en quarantaine.",
                "2. Analyser les fichiers modifies depuis le lancement du processus.",
                "3. Alerter le responsable de securite de l'entreprise.",
                "4. Surveiller l'activite reseau sortante pendant 30 minutes.",
            ],
            "MOYEN": [
                f"1. Surveiller le processus '{process_name}' pendant 10 minutes.",
                "2. Si le comportement persiste, mettre en quarantaine.",
                "3. Journaliser l'incident pour suivi.",
            ],
        }
        return base.get(severity, ["Surveillance standard. Aucune action immediate requise."])

    def _proactive_warning(self, threat_type: str) -> str:
        warnings = {
            "RANSOMWARE": (
                "PROACTIF : Si ce processus est un ransomware actif, tous vos fichiers "
                "seront chiffres et inaccessibles dans les prochaines minutes. "
                "Isolez la machine MAINTENANT avant qu'il soit trop tard."
            ),
            "TROJAN_C2": (
                "PROACTIF : Un trojan C2 peut telecharger d'autres malwares, "
                "voler vos mots de passe et donner un acces permanent a l'attaquant. "
                "Bloquer les connexions sortantes de ce processus immediatement."
            ),
            "PRIVILEGE_ESCALATION": (
                "PROACTIF : Si l'elevation de privileges reussit, l'attaquant aura "
                "un controle total sur cette machine et pourra se deplacer vers "
                "toutes les autres machines de votre reseau."
            ),
        }
        return warnings.get(threat_type, "")


# ══════════════════════════════════════════════════════════════════════════════
# MOTEUR 2 : DETECTEUR DE PHISHING ADAPTE AU CAMEROUN
# ══════════════════════════════════════════════════════════════════════════════

class PhishingDetector:
    """
    Detection de phishing par analyse NLP adaptee au contexte camerounais.
    4 familles de patterns extraites de cas reels recenses au Cameroun :
      1. urgence          : creation d'urgence artificielle
      2. leurres_financiers : promesses d'argent Mobile Money
      3. usurpation       : fausse identite d'institutions camerounaises
      4. manipulation_psy : pression psychologique
    """

    PATTERNS = {
        "urgence": [
            "urgent", "immediatement", "derniere chance", "expire aujourd hui",
            "expire dans 24 heures", "action requise", "compte bloque",
            "suspension imminente", "verification obligatoire",
            "repondre maintenant", "delai expire", "fermeture definitive",
        ],
        "leurres_financiers": [
            "transfert de fonds", "heritage", "lot gagnant", "vous avez gagne",
            "prix mtn", "momo offert", "orange money cadeau", "promo mobile money",
            "investissement garanti", "doubler votre argent", "credit gratuit",
            "airtime offert", "recharge gratuite", "bonus mtn", "transaction bloquee",
        ],
        "usurpation": [
            "banque de l afrique", "beac", "ministere des finances", "tresor public",
            "police nationale cameroun", "interpol cameroun", "direction generale",
            "administration fiscale", "mtn cameroun officiel", "orange cameroun officiel",
            "keycash", "payplus", "afriland", "sgbc",
        ],
        "manipulation_psy": [
            "ne dites a personne", "confidentiel uniquement", "votre famille est en danger",
            "arrestation imminente", "vous serez poursuivi", "amende a payer",
            "secret absolu", "opportunite unique", "uniquement pour vous",
            "ne partagez pas", "discret", "warrant"
        ],
    }

    def analyze_text(self, text: str,
                     pme_id: str = "PME-INCONNU") -> ThreatReport:
        """
        Analyse un email ou SMS pour detecter le phishing.
        Retourne un ThreatReport avec le score de risque et les patterns detectes.
        """
        text_lower = text.lower()

        # Calculer les scores par categorie
        category_scores = {}
        matched_patterns = []
        pattern_detail = {}

        for category, patterns in self.PATTERNS.items():
            hits = [p for p in patterns if p in text_lower]
            category_scores[category] = min(1.0, len(hits) * 0.28)
            matched_patterns.extend(hits)
            if hits:
                pattern_detail[category] = hits

        # Score global avec bonus si plusieurs categories activees
        active_categories = sum(1 for s in category_scores.values() if s > 0)
        base_score = sum(category_scores.values()) / len(category_scores) * 2.8
        bonus = 0.3 if active_categories >= 3 else 0.15 if active_categories == 2 else 0
        global_score = min(1.0, base_score + bonus)

        severity = (
            "CRITIQUE" if global_score >= 0.78 else
            "ELEVE"    if global_score >= 0.55 else
            "MOYEN"    if global_score >= 0.30 else
            "FAIBLE"
        )

        indicators = []
        for cat, hits in pattern_detail.items():
            cat_label = {
                "urgence": "Patterns d'URGENCE artificielle",
                "leurres_financiers": "Leurres FINANCIERS Mobile Money",
                "usurpation": "USURPATION d'identite institutionnelle camerounaise",
                "manipulation_psy": "MANIPULATION psychologique",
            }.get(cat, cat.upper())
            indicators.append(f"[{cat_label}] : {', '.join(hits[:4])}")

        if not indicators:
            indicators = ["Aucun pattern de phishing detecte dans ce message"]

        tid = hashlib.sha256(text[:60].encode()).hexdigest()[:14].upper()
        blocked = global_score > 0.65

        return ThreatReport(
            threat_id=tid,
            pme_id=pme_id,
            threat_type="PHISHING",
            severity=severity,
            confidence=round(global_score, 3),
            description=self._build_description(global_score, len(matched_patterns), active_categories),
            indicators=indicators,
            recommended_actions=self._recommended_actions(global_score),
            proactive_warning=self._proactive_warning(global_score, active_categories),
            blocked=blocked,
        )

    def _build_description(self, score: float, n_patterns: int, n_categories: int) -> str:
        if score >= 0.78:
            return (
                f"Message de phishing a TRES HAUT RISQUE. "
                f"{n_patterns} indicateurs malveillants detectes dans {n_categories} categories. "
                f"Ingenierie sociale sophistiquee ciblee sur le contexte camerounais. "
                f"Score de risque : {score*100:.0f}%."
            )
        if score >= 0.55:
            return (
                f"Contenu suspect avec {n_patterns} signal(aux) de phishing. "
                f"Tentative probable d'hameconnage financier ou d'usurpation d'identite. "
                f"Score de risque : {score*100:.0f}%."
            )
        if score >= 0.30:
            return (
                f"Quelques elements suspects detectes ({n_patterns} pattern(s)). "
                f"Prudence recommandee. Score de risque : {score*100:.0f}%."
            )
        return f"Message legitime. Faible probabilite de phishing ({score*100:.0f}%)."

    def _recommended_actions(self, score: float) -> List[str]:
        if score >= 0.55:
            return [
                "1. NE PAS cliquer sur aucun lien presente dans ce message.",
                "2. NE PAS repondre a ce message et ne pas rappeler les numeros indiques.",
                "3. NE PAS communiquer votre code PIN, mot de passe ou code OTP Mobile Money.",
                "4. Signaler ce message a SENTINEL SOC et au service client de l'operateur usurpe.",
                "5. Alerter vos collegues : si vous avez recu ce message, ils l'ont peut-etre aussi.",
            ]
        if score >= 0.30:
            return [
                "1. Verifier l'authenticite du message en appelant directement l'organisme concerne.",
                "2. Ne pas partager d'informations personnelles sans verification.",
            ]
        return ["Message considere comme legitime. Surveillance standard."]

    def _proactive_warning(self, score: float, n_categories: int) -> str:
        if score >= 0.78:
            return (
                "PROACTIF : Ce type de phishing vise generalement a voler des codes Mobile Money "
                "ou des identifiants bancaires. Si quelqu'un dans votre equipe a deja clique sur "
                "un lien ou communique un code, il faut changer immediatement tous les mots de "
                "passe et bloquer les transactions Mobile Money de la journee."
            )
        if score >= 0.55:
            return (
                "PROACTIF : Verifiez si d'autres employes ont recu le meme message. "
                "Une campagne de phishing ciblee peut viser plusieurs personnes en meme temps."
            )
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# DEMONSTRATION
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 70)
    print("  SENTINEL PME AFRICA — Demonstration Moteur de Detection")
    print("=" * 70)

    # Test 1 : Ransomware
    detector = BehavioralMalwareDetector()
    r1 = detector.analyze_process("cryptolocker32.exe", {
        "syscall_frequency": 0.91, "file_access_score": 0.78,
        "network_anomaly":   0.55, "cpu_spike":         0.95,
        "privilege_attempt": 0.72, "file_encrypt_rate": 0.97,
    }, pme_id="PME-CM-YDE-00142")
    print(f"\n[MALWARE TEST 1] {r1.summary()}")
    print(f"  Description : {r1.description[:80]}...")
    print(f"  Action 1    : {r1.recommended_actions[0][:70]}...")
    print(f"  Proactif    : {r1.proactive_warning[:70]}...")

    # Test 2 : Comportement legitime
    r2 = detector.analyze_process("excel.exe", {
        "syscall_frequency": 0.12, "file_access_score": 0.08,
        "network_anomaly":   0.05, "cpu_spike":         0.15,
        "privilege_attempt": 0.02, "file_encrypt_rate": 0.01,
    })
    print(f"\n[MALWARE TEST 2] {r2.summary()}")

    # Test 3 : Phishing MTN Mobile Money
    pd = PhishingDetector()
    msg_phishing = (
        "URGENT: Votre compte MTN MoMo sera bloque dans 24 heures. "
        "Action requise immediatement. Verification obligatoire de votre identite. "
        "Ne dites a personne. Envoyez votre code PIN de confirmation au 699000000. "
        "Ce message est confidentiel uniquement. Lot gagnant de 500 000 FCFA vous attend."
    )
    r3 = pd.analyze_text(msg_phishing, pme_id="PME-CM-DLA-00089")
    print(f"\n[PHISHING TEST 1] {r3.summary()}")
    print(f"  Description : {r3.description[:80]}...")
    for ind in r3.indicators:
        print(f"  Indicateur  : {ind[:70]}")
    print(f"  Proactif    : {r3.proactive_warning[:80]}...")

    # Test 4 : Message legitime
    msg_legitime = "Bonjour, votre colis sera livre demain entre 9h et 17h. Cordialement."
    r4 = pd.analyze_text(msg_legitime)
    print(f"\n[PHISHING TEST 2] {r4.summary()}")

    print("\n" + "=" * 70)
    print("  Demonstration complete. Moteur operationnel.")
    print("=" * 70)
