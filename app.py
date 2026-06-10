"""
ERM·OSINT — Backend Flask
Lance avec : python app.py
Accès       : http://localhost:5050
Dépendances : pip install flask flask-cors feedparser requests beautifulsoup4
"""
from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import feedparser, requests, json, re, threading
from bs4 import BeautifulSoup
from datetime import datetime
import os

app  = Flask(__name__, static_folder='.')
CORS(app)

RSS_FEEDS = [
    {"name": "CERT-FR",               "url": "https://www.cert.ssi.gouv.fr/feed/",             "cat": "Cyber",         "w": 3},
    {"name": "ANSSI",                  "url": "https://www.ssi.gouv.fr/actualite/rss.xml",       "cat": "Cyber",         "w": 3},
    {"name": "Cybermalveillance.gouv", "url": "https://www.cybermalveillance.gouv.fr/rss",       "cat": "Cyber",         "w": 3},
    {"name": "Banque de France",       "url": "https://www.banque-france.fr/rss-actualites",     "cat": "Réglementaire", "w": 2},
    {"name": "Les Échos Finance",      "url": "https://feeds.lesechos.fr/rss/rss-finance.xml",   "cat": "Réputation",    "w": 2},
    {"name": "CNIL",                   "url": "https://www.cnil.fr/rss.xml",                     "cat": "Réglementaire", "w": 2},
]

RISK_KEYWORDS = {
    "Cyber": {
        "critical": ["ransomware","rançongiciel","cyberattaque","zero-day","0day","data breach","intrusion","malware","phishing","APT","compromission","fuite de données","darkweb","botnet","DDoS","activement exploitée","exploitation active"],
        "medium":   ["vulnérabilité","patch","mise à jour sécurité","élévation de privilèges","contournement","atteinte à la confidentialité","credential"],
        "low":      ["informatique","numérique","cloud","infrastructure","linux","windows","microsoft","cisco"],
    },
    "Réglementaire": {
        "critical": ["DORA","NIS2","sanction","amende","mise en demeure","ACPR","AMF","non-conformité","infraction","pénalité","RGPD violation"],
        "medium":   ["réglementation","conformité","directive","règlement","obligation","audit","contrôle","RGPD","protection des données"],
        "low":      ["législation","loi","décret"],
    },
    "Réputation": {
        "critical": ["scandale","fraude","détournement","corruption","faillite","plainte collective","bad buzz","boycott"],
        "medium":   ["controverse","critique","insatisfaction","plainte","rumeur"],
        "low":      ["communication","presse","médias"],
    },
    "Fraude": {
        "critical": ["fraude","escroquerie","blanchiment","financement terrorisme","virement frauduleux","usurpation","deepfake","arnaque"],
        "medium":   ["suspect","anomalie","transaction inhabituelle","ingénierie sociale"],
        "low":      ["vigilance","prévention"],
    },
}

state = {
    "signals": [], "risks": {
        "Cyber":         {"level":"Faible","score":15,"trend":"stable","kri":20},
        "Réglementaire": {"level":"Faible","score":10,"trend":"stable","kri":15},
        "Réputation":    {"level":"Faible","score":8, "trend":"stable","kri":12},
        "Fraude":        {"level":"Faible","score":5, "trend":"stable","kri":8},
    },
    "last_update": None, "alerts": [], "loading": False,
    "stats": {"total":0,"critical":0,"medium":0,"low":0},
}

def level(score):
    return "Élevé" if score>=70 else "Moyen" if score>=35 else "Faible"

def analyze(title, summary, src_cat, w):
    text = (title+" "+summary).lower()
    best_cat, best_lv, best_score, best_kw = src_cat, "low", 0, []
    for cat, levels in RISK_KEYWORDS.items():
        for lv, kws in levels.items():
            for kw in kws:
                if kw.lower() in text:
                    m={"critical":3,"medium":2,"low":1}[lv]
                    s=m*w*10
                    if s>best_score:
                        best_score,best_cat,best_lv,best_kw=s,cat,lv,[kw]
                    elif s==best_score and kw not in best_kw:
                        best_kw.append(kw)
    return {"category":best_cat,"criticality":{"critical":"Élevé","medium":"Moyen","low":"Faible"}[best_lv],"score":min(best_score,100),"keywords":best_kw[:3]}

def fetch_all():
    global state
    state["loading"] = True
    sigs = []
    for f in RSS_FEEDS:
        try:
            feed = feedparser.parse(f["url"])
            for e in feed.entries[:6]:
                title   = e.get("title","")[:120]
                raw     = e.get("summary", e.get("description",""))
                summary = BeautifulSoup(raw,"html.parser").get_text()[:300] if raw else ""
                a = analyze(title, summary, f["cat"], f["w"])
                sigs.append({"id": abs(hash(title+f["name"]))%100000, "title": title,
                              "summary": summary, "link": e.get("link","#"),
                              "date": e.get("published","")[:16], "source": f["name"], **a})
            print(f"  ✓ {f['name']}: {len(feed.entries)} entrées")
        except Exception as ex:
            print(f"  ✗ {f['name']}: {ex}")

    seen, unique = set(), []
    for s in sigs:
        if s["id"] not in seen:
            seen.add(s["id"]); unique.append(s)
    unique.sort(key=lambda x: x["score"], reverse=True)

    new_risks = {}
    for cat in ["Cyber","Réglementaire","Réputation","Fraude"]:
        scores = [s["score"] for s in unique if s["category"]==cat]
        if scores:
            total = min(int(sum(scores)/len(scores)*0.6 + max(scores)*0.4), 100)
            old = state["risks"].get(cat,{}).get("score",0)
            trend = "hausse" if total>old+10 else "baisse" if total<old-10 else "stable"
        else:
            total, trend = 10, "stable"
        new_risks[cat] = {"level":level(total),"score":total,"trend":trend,"kri":min(total+5,100)}

    state.update({
        "signals": unique,
        "risks": new_risks,
        "alerts": [{"id":s["id"],"title":s["title"],"source":s["source"],"category":s["category"],"time":s["date"]} for s in unique if s["criticality"]=="Élevé"][:5],
        "stats": {"total":len(unique),"critical":sum(1 for s in unique if s["criticality"]=="Élevé"),"medium":sum(1 for s in unique if s["criticality"]=="Moyen"),"low":sum(1 for s in unique if s["criticality"]=="Faible")},
        "last_update": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "loading": False,
    })
    print(f"[{state['last_update']}] {state['stats']['total']} signaux — {state['stats']['critical']} critiques")

@app.route("/")
def index():
    return send_from_directory(".", "ERM_OSINT_Dashboard.html")

@app.route("/api/status")
def api_status():
    return jsonify({"last_update":state["last_update"],"loading":state["loading"],"stats":state["stats"]})

@app.route("/api/risks")
def api_risks():
    return jsonify(state["risks"])

@app.route("/api/signals")
def api_signals():
    return jsonify(state["signals"])

@app.route("/api/alerts")
def api_alerts():
    return jsonify(state["alerts"])

@app.route("/api/refresh")
def api_refresh():
    t = threading.Thread(target=fetch_all, daemon=True)
    t.start()
    return jsonify({"status":"started"})

if __name__ == "__main__":
    print("=" * 55)
    print("  ERM·OSINT — Risk Intelligence Platform")
    print("=" * 55)
    print("Collecte initiale des flux OSINT...")
    fetch_all()
    print(f"\nOuvrez : http://localhost:5050\n")
    app.run(host="0.0.0.0", port=5050, debug=False)
