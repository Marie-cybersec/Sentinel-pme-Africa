"""
SENTINEL PME AFRICA — Serveur SOC Central
==========================================
Inspire de l'architecture Wazuh Manager.
Installe sur Ubuntu Server 22.04 LTS (192.168.56.30).

Usage:
    pip3 install fastapi uvicorn websockets python-multipart cryptography
    python3 soc_server.py

Acces dashboard : http://192.168.157.10:8080/dashboard.html
API docs        : http://192.168.157.10:8000/docs
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
from typing import List
import asyncio, json, uvicorn, hashlib

app = FastAPI(
    title="SENTINEL PME Africa — SOC API",
    description="Systeme de detection d'intrusion pour PME camerounaises",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Stockage en memoire ────────────────────────────────────────────────────────
alerts:     List[dict] = []   # toutes les alertes recues
agents:     dict       = {}   # dernier heartbeat par pme_id
ws_clients: List[WebSocket] = []  # connexions WebSocket actives

# ── Calcul du score de risque global (0 a 100) ────────────────────────────────
def compute_risk_score() -> int:
    if not alerts:
        return 0
    recent = alerts[-20:]  # 20 dernieres alertes
    score = 0
    for a in recent:
        s = a.get("severity", "FAIBLE")
        if s == "CRITIQUE": score += 35
        elif s == "ELEVE":  score += 20
        elif s == "MOYEN":  score += 10
        else:               score += 3
    return min(100, score)

def risk_label(score: int) -> str:
    if score >= 70: return "CRITIQUE"
    if score >= 40: return "ELEVE"
    if score >= 15: return "MOYEN"
    return "FAIBLE"

# ── Statistiques par type ──────────────────────────────────────────────────────
def compute_stats() -> dict:
    by_type = {}
    by_sev  = {"CRITIQUE": 0, "ELEVE": 0, "MOYEN": 0, "FAIBLE": 0}
    for a in alerts:
        t = a.get("threat_type", "INCONNU")
        by_type[t] = by_type.get(t, 0) + 1
        s = a.get("severity", "FAIBLE")
        if s in by_sev:
            by_sev[s] += 1
    score = compute_risk_score()
    return {
        "total_alerts":  len(alerts),
        "risk_score":    score,
        "risk_label":    risk_label(score),
        "by_type":       by_type,
        "by_severity":   by_sev,
        "agents_online": len(agents),
    }

# ── Broadcast WebSocket vers tous les navigateurs connectes ───────────────────
async def broadcast(message: dict):
    dead = []
    for ws in ws_clients:
        try:
            await ws.send_json(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in ws_clients:
            ws_clients.remove(ws)

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES API
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/")
async def root():
    return {
        "service": "SENTINEL PME Africa",
        "version": "1.0.0",
        "status":  "running",
        "docs":    "/docs",
        "dashboard": "http://192.168.157.10:8080/dashboard.html"
    }


@app.post("/api/alerts")
async def receive_alert(alert: dict):
    """
    Recoit une alerte depuis l'agent SENTINEL installe sur Windows.
    Verifie les champs obligatoires, enregistre et diffuse en temps reel.
    """
    # Validation minimale
    required = ["threat_type", "severity", "description", "pme_id"]
    for field in required:
        if field not in alert:
            return {"status": "error", "message": f"Champ manquant : {field}"}

    alert["received_at"] = datetime.now(timezone.utc).isoformat() + "Z"
    alert["alert_index"] = len(alerts) + 1

    alerts.append(alert)

    score = compute_risk_score()
    label = risk_label(score)

    print(f"[SOC] ALERTE #{alert['alert_index']} | {alert['threat_type']} | "
          f"{alert['severity']} | {alert.get('source_ip', '?')} | "
          f"Score risque : {score}/100")

    # Diffuser en temps reel vers tous les dashboards connectes
    await broadcast({
        "type":       "NEW_ALERT",
        "alert":      alert,
        "risk_score": score,
        "risk_label": label,
        "stats":      compute_stats(),
    })

    return {
        "status":     "ok",
        "threat_id":  alert.get("threat_id"),
        "risk_score": score,
        "risk_label": label,
    }


@app.post("/api/heartbeat")
async def heartbeat(data: dict):
    """
    Recoit le signal de vie de l'agent toutes les 30 secondes.
    Met a jour l'etat de la machine dans le panneau Agents.
    """
    pme_id = data.get("pme_id", "inconnu")
    data["last_seen"] = datetime.now(timezone.utc).isoformat() + "Z"
    agents[pme_id] = data

    await broadcast({
        "type":  "HEARTBEAT",
        "agent": data,
    })
    return {"status": "ok"}


@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    """Retourne les dernieres alertes avec les statistiques globales."""
    return {
        "alerts":     alerts[-limit:],
        "total":      len(alerts),
        "risk_score": compute_risk_score(),
        "risk_label": risk_label(compute_risk_score()),
    }


@app.get("/api/stats")
async def get_stats():
    """Statistiques globales pour le dashboard."""
    return compute_stats()


@app.get("/api/agents")
async def get_agents():
    """Etat de tous les agents SENTINEL connectes."""
    return list(agents.values())


@app.delete("/api/alerts")
async def clear_alerts():
    """Remet a zero toutes les alertes (entre deux demonstrations)."""
    alerts.clear()
    await broadcast({"type": "CLEAR"})
    return {"status": "ok", "message": "Tableau de bord reinitialise"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Endpoint WebSocket pour les mises a jour en temps reel.
    Chaque navigateur ouvert sur le dashboard maintient une connexion ici.
    """
    await websocket.accept()
    ws_clients.append(websocket)
    print(f"[SOC] Dashboard connecte ({len(ws_clients)} navigateur(s) actif(s))")

    try:
        # Envoyer l'etat complet au nouveau dashboard qui se connecte
        await websocket.send_json({
            "type":       "INIT",
            "alerts":     alerts[-30:],
            "risk_score": compute_risk_score(),
            "risk_label": risk_label(compute_risk_score()),
            "agents":     list(agents.values()),
            "stats":      compute_stats(),
        })
        # Maintenir la connexion ouverte
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in ws_clients:
            ws_clients.remove(websocket)
        print(f"[SOC] Dashboard deconnecte ({len(ws_clients)} navigateur(s) actif(s))")


# ══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTREE
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║       SENTINEL PME AFRICA — Serveur SOC v1.0.0               ║
║                                                              ║
║  API REST  : http://0.0.0.0:8000                             ║
║  WebSocket : ws://0.0.0.0:8000/ws                            ║
║  Docs API  : http://192.168.157.10:8000/docs                  ║
║                                                              ║
║  Dashboard : http://192.168.157.10:8080/dashboard.html        ║
║  (lancer aussi : python3 -m http.server 8080)                ║
╚══════════════════════════════════════════════════════════════╝
""")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
