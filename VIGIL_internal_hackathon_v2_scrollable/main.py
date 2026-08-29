"""
VIGIL — Internal Hackathon Prototype v2
FastAPI + spaCy + NetworkX

Prototype scope:
- JWT-style demo RBAC (in-memory users)
- Tamper-evident SHA-256 hash-chained audit log
- Optional Fernet encryption helpers for sensitive-at-rest demo values
- spaCy NER + EntityRuler + regex extractors
- NetworkX weighted co-occurrence graph
- Degree/betweenness/community/articulation analytics
- Explainable rule-based alerts
- Structured evidence returned for UI drill-down
Run:
    pip install -r requirements.txt
    python -m spacy download en_core_web_sm   # or install the wheel directly
    uvicorn main:app --reload
Then open http://127.0.0.1:8000
IMPORTANT:
This remains a SYNTHETIC-DATA prototype. The security controls are demo-grade
and must be replaced/hardened before real law-enforcement deployment.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import networkx as nx
import spacy
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# --------------------------------------------------------------------------
# 1. NLP
# --------------------------------------------------------------------------

nlp = spacy.load("en_core_web_sm")

KNOWN_PERSONS = [
    "Rahul Verma", "Sunil Yadav", "Amit Kumar", "Priya Singh",
    "Vikas Rana", "Deepak Chauhan", "Meena Devi", "Suresh Thakur",
    "Anil Mishra", "Rakesh Oza", "Aman Kapoor"
]
KNOWN_LOCATIONS = [
    "Gandhi Maidan, Patna", "Gandhi Maidan", "Patna", "Danapur",
    "Kankarbagh", "Bihta", "Muzaffarpur"
]
KNOWN_ORGS = ["Shree Traders", "Ganga Logistics", "NorthStar Finance Co-op"]

try:
    ruler = nlp.add_pipe("entity_ruler", before="ner")
except ValueError:
    ruler = nlp.get_pipe("entity_ruler")

patterns = []
patterns += [{"label": "PERSON", "pattern": p} for p in KNOWN_PERSONS]
patterns += [{"label": "GPE", "pattern": p} for p in KNOWN_LOCATIONS]
patterns += [{"label": "ORG", "pattern": p} for p in KNOWN_ORGS]
ruler.add_patterns(patterns)

PHONE_RE = re.compile(r"\+91-\d{5}-\d{5}")
VEHICLE_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z]{2}\d{3,4}\b")
AMOUNT_RE = re.compile(r"₹\s?[\d,]+")
LABEL_MAP = {"PERSON": "person", "GPE": "location", "LOC": "location", "ORG": "org"}

def extract_entities(text: str) -> List[Dict[str, str]]:
    doc = nlp(text)
    found: Dict[str, str] = {}
    for ent in doc.ents:
        if ent.label_ in LABEL_MAP:
            found[ent.text] = LABEL_MAP[ent.label_]
    for m in PHONE_RE.findall(text):
        found[m] = "phone"
    for m in VEHICLE_RE.findall(text):
        found[m] = "vehicle"
    return [{"text": k, "type": v} for k, v in found.items()]

# --------------------------------------------------------------------------
# 2. RBAC (demo-grade)
# --------------------------------------------------------------------------

DEMO_USERS = {
    "investigator": {"password": "vigil123", "role": "INVESTIGATOR", "district": "Patna"},
    "district_admin": {"password": "vigil123", "role": "DISTRICT_ADMIN", "district": "Patna"},
    "state_admin": {"password": "vigil123", "role": "STATE_ADMIN", "district": "Bihar"},
}

ROLE_LEVEL = {"INVESTIGATOR": 1, "DISTRICT_ADMIN": 2, "STATE_ADMIN": 3}
TOKENS: Dict[str, Dict[str, str]] = {}

def issue_token(username: str) -> str:
    token = secrets.token_urlsafe(32)
    user = DEMO_USERS[username]
    TOKENS[token] = {"username": username, "role": user["role"], "district": user["district"]}
    return token

def current_user(authorization: Optional[str] = Header(default=None)) -> Dict[str, str]:
    if not authorization:
        # Demo convenience: allow anonymous read-only access to synthetic data.
        return {"username": "demo", "role": "INVESTIGATOR", "district": "Patna"}
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Use Bearer <token>")
    token = authorization.split(" ", 1)[1].strip()
    user = TOKENS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired demo token")
    return user

def require_role(min_role: str):
    def checker(user: Dict[str, str] = Depends(current_user)):
        if ROLE_LEVEL[user["role"]] < ROLE_LEVEL[min_role]:
            raise HTTPException(status_code=403, detail=f"{min_role} or higher required")
        return user
    return checker

# --------------------------------------------------------------------------
# 3. Audit hash chain
# --------------------------------------------------------------------------

AUDIT_LOG: List[Dict[str, Any]] = []

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _audit_hash(payload: Dict[str, Any], previous_hash: str) -> str:
    body = json.dumps(
        {"previous_hash": previous_hash, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(body).hexdigest()

def audit(action: str, details: Dict[str, Any], user: Dict[str, str]) -> Dict[str, Any]:
    previous = AUDIT_LOG[-1]["hash"] if AUDIT_LOG else "GENESIS"
    payload = {
        "timestamp": now_iso(),
        "username": user["username"],
        "role": user["role"],
        "action": action,
        "details": details,
    }
    digest = _audit_hash(payload, previous)
    event = {**payload, "previous_hash": previous, "hash": digest}
    AUDIT_LOG.append(event)
    return event

def verify_audit_chain() -> Dict[str, Any]:
    previous = "GENESIS"
    for idx, event in enumerate(AUDIT_LOG):
        payload = {
            "timestamp": event["timestamp"],
            "username": event["username"],
            "role": event["role"],
            "action": event["action"],
            "details": event["details"],
        }
        expected = _audit_hash(payload, previous)
        if event["hash"] != expected or event["previous_hash"] != previous:
            return {"valid": False, "broken_at": idx, "records_checked": idx}
        previous = event["hash"]
    return {"valid": True, "records_checked": len(AUDIT_LOG)}

# --------------------------------------------------------------------------
# 4. Encryption helpers (demo-grade at-rest helper)
# --------------------------------------------------------------------------

FERNET_KEY = os.getenv("VIGIL_FERNET_KEY")
if not FERNET_KEY:
    FERNET_KEY = Fernet.generate_key().decode()
cipher = Fernet(FERNET_KEY.encode())

def encrypt_value(value: str) -> str:
    return cipher.encrypt(value.encode()).decode()

def decrypt_value(value: str) -> str:
    try:
        return cipher.decrypt(value.encode()).decode()
    except InvalidToken:
        raise HTTPException(status_code=400, detail="Encrypted value could not be decrypted")

# --------------------------------------------------------------------------
# 5. Graph
# --------------------------------------------------------------------------

def build_graph(records: List[Dict[str, Any]]) -> nx.Graph:
    G = nx.Graph()
    for r in records:
        ents = r["entities"]
        for e in ents:
            if not G.has_node(e["text"]):
                G.add_node(e["text"], type=e["type"], records=set())
            G.nodes[e["text"]]["records"].add(r["id"])
        for i in range(len(ents)):
            for j in range(i + 1, len(ents)):
                a, b = ents[i]["text"], ents[j]["text"]
                w = r.get("weight", 1)
                if G.has_edge(a, b):
                    G[a][b]["weight"] += w
                    G[a][b]["records"].append(r["id"])
                    G[a][b]["source_types"].add(r["source"])
                else:
                    G.add_edge(
                        a, b,
                        weight=w,
                        records=[r["id"]],
                        source_types={r["source"]},
                    )
    for u, v in G.edges():
        srcs = G[u][v]["source_types"]
        G[u][v]["confidence"] = "verified" if len(srcs) >= 2 else "unverified"
        G[u][v]["evidence_status"] = (
            "CORROBORATED" if len(srcs) >= 2 else "SINGLE-SOURCE"
        )
    return G

def run_analytics(G: nx.Graph) -> Dict[str, Any]:
    degree_c = nx.degree_centrality(G)
    between_c = nx.betweenness_centrality(G, weight=None, normalized=True)
    max_deg = max(degree_c.values()) if degree_c else 1
    max_bet = max(between_c.values()) if between_c else 1

    influence = {
        n: round(
            0.5 * (degree_c[n] / max_deg if max_deg else 0)
            + 0.5 * (between_c[n] / max_bet if max_bet else 0),
            4,
        )
        for n in G.nodes
    }

    communities = list(nx.algorithms.community.greedy_modularity_communities(G, weight="weight"))
    community_of: Dict[str, int] = {}
    for idx, c in enumerate(communities):
        for n in c:
            community_of[n] = idx

    articulation: List[str] = []
    for comp in nx.connected_components(G):
        sub = G.subgraph(comp)
        articulation.extend(list(nx.articulation_points(sub)))

    return {
        "degree_centrality": degree_c,
        "betweenness_centrality": between_c,
        "influence": influence,
        "community_of": community_of,
        "num_communities": len(communities),
        "articulation_points": articulation,
    }

# --------------------------------------------------------------------------
# 6. Explainable alerts
# --------------------------------------------------------------------------

def detect_alerts(records: List[Dict[str, Any]], G: nx.Graph, analytics: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []

    record_map = {r["id"]: r for r in records}
    record_source = {r["id"]: r["source"] for r in records}

    # High call frequency
    for r in records:
        if r["source"] == "CDR":
            m = re.search(r"(\d+)\s+times", r["text"])
            if m and int(m.group(1)) >= 15:
                entities = [e["text"] for e in r["entities"]]
                alerts.append({
                    "title": "Unusual call frequency",
                    "severity": "lead",
                    "category": "Communication",
                    "record_ids": [r["id"]],
                    "entities": entities,
                    "source_types": [r["source"]],
                    "metric": f"{m.group(1)} contacts",
                    "explanation": "High-frequency communication pattern detected in CDR data.",
                    "text": f"{r['id']}: {m.group(1)} contacts recorded.",
                })

    # Structuring
    for r in records:
        if r["source"] == "Bank" and ("split" in r["text"].lower() or "transactions to avoid" in r["text"].lower()):
            amt = AMOUNT_RE.search(r["text"])
            alerts.append({
                "title": "Possible structuring (smurfing)",
                "severity": "lead",
                "category": "Financial",
                "record_ids": [r["id"]],
                "entities": [e["text"] for e in r["entities"]],
                "source_types": [r["source"]],
                "metric": amt.group(0) if amt else "Split transaction",
                "explanation": "A transaction appears to have been divided into multiple parts.",
                "text": f"{r['id']}: transaction {amt.group(0) if amt else ''} appears split.",
            })

    # Broker / bridge
    aps = sorted(
        analytics["articulation_points"],
        key=lambda n: analytics["influence"].get(n, 0),
        reverse=True,
    )
    if aps:
        for n in aps[:2]:
            recs = list(G.nodes[n]["records"])
            alerts.append({
                "title": "Cluster-bridging entity detected",
                "severity": "lead",
                "category": "Network",
                "record_ids": recs[:6],
                "entities": [n],
                "source_types": sorted({record_source[x] for x in recs}),
                "metric": f"Influence {(analytics['influence'].get(n, 0) * 100):.0f}/100",
                "explanation": "Removing this node would split the network into disconnected components.",
                "text": f"{n} is a cut-vertex and a strong broker/middleman candidate.",
            })

    # Cross-community links
    com = analytics["community_of"]
    cross_pairs = []
    for u, v, data in G.edges(data=True):
        if com.get(u) != com.get(v):
            score = analytics["influence"].get(u, 0) + analytics["influence"].get(v, 0)
            cross_pairs.append((score, u, v, data))
    cross_pairs.sort(reverse=True, key=lambda x: x[0])
    for _, u, v, data in cross_pairs[:3]:
        alerts.append({
            "title": "Unexplained cross-cluster link",
            "severity": "lead",
            "category": "Network",
            "record_ids": list(data["records"])[:6],
            "entities": [u, v],
            "source_types": sorted(data["source_types"]),
            "metric": f"Weight {data['weight']}",
            "explanation": "These entities belong to separate communities but are directly linked.",
            "text": f"{u} ↔ {v} may represent a hand-off point between operations.",
        })

    # Uncorroborated accusations
    accused_by = defaultdict(set)
    for r in records:
        complainant = r.get("complainant")
        if r["source"] == "FIR" and complainant:
            for e in r["entities"]:
                if e["text"] != complainant and e["type"] == "person":
                    accused_by[e["text"]].add(complainant)

    for person, complainants in accused_by.items():
        if person not in G:
            continue
        source_types_seen = {record_source[rid] for rid in G.nodes[person]["records"]}
        if source_types_seen == {"FIR"}:
            recs = list(G.nodes[person]["records"])
            alerts.append({
                "title": "Uncorroborated accusation — needs verification",
                "severity": "caution",
                "category": "Evidence",
                "record_ids": recs,
                "entities": [person, *sorted(complainants)],
                "source_types": ["FIR"],
                "metric": "FIR only",
                "explanation": "No independent CDR, bank, surveillance or social source corroborates the accusation.",
                "text": f"{person} is named only in FIR complaint(s). Treat as unverified.",
            })

    # Possible malicious complaint pattern
    pair_counts = defaultdict(list)
    for r in records:
        complainant = r.get("complainant")
        if r["source"] == "FIR" and complainant:
            for e in r["entities"]:
                if e["text"] != complainant and e["type"] == "person":
                    pair_counts[(complainant, e["text"])].append(r["id"])

    for (complainant, accused), record_ids in pair_counts.items():
        source_types_seen = (
            {record_source[rid] for rid in G.nodes[accused]["records"]}
            if accused in G else set()
        )
        if len(record_ids) >= 2 and not (source_types_seen - {"FIR"}):
            alerts.append({
                "title": "Possible malicious complaint pattern",
                "severity": "caution",
                "category": "Evidence",
                "record_ids": record_ids,
                "entities": [complainant, accused],
                "source_types": ["FIR"],
                "metric": f"{len(record_ids)} FIRs",
                "explanation": "The same complainant repeatedly names the same person with no independent source support.",
                "text": f"{complainant} repeatedly names {accused} without independent corroboration.",
            })
    return alerts

# --------------------------------------------------------------------------
# 7. Demo data
# --------------------------------------------------------------------------

SAMPLE_RECORDS = [
    {"id": "FIR-2091", "source": "FIR", "weight": 3, "complainant": "Patna Police (raid)",
     "text": "Patna Police recovered records linking Rahul Verma with Sunil Yadav and a logistics activity near Gandhi Maidan, Patna."},
    {"id": "CDR-4471", "source": "CDR", "weight": 5,
     "text": "Rahul Verma contacted Sunil Yadav 47 times over 6 days using +91-98765-43210. Night-time traffic was unusually high."},
    {"id": "BANK-7723", "source": "Bank", "weight": 4,
     "text": "Amit Kumar transferred ₹2,40,000 to Shree Traders and the amount was split into multiple transactions to avoid mandatory reporting."},
    {"id": "SURV-3302", "source": "Surveillance", "weight": 4,
     "text": "Sunil Yadav and Amit Kumar were observed meeting near Kankarbagh beside vehicle BR01AB1234."},
    {"id": "SOC-1154", "source": "Social", "weight": 2,
     "text": "Priya Singh shared a location from Danapur and later interacted with Rahul Verma through a public group."},
    {"id": "FIR-2092", "source": "FIR", "weight": 2, "complainant": "Meena Devi",
     "text": "Meena Devi stated that Rahul Verma met Sunil Yadav near Gandhi Maidan and mentioned Ganga Logistics."},
    {"id": "CDR-4472", "source": "CDR", "weight": 3,
     "text": "Sunil Yadav contacted Amit Kumar 23 times in 3 days from a phone linked to +91-91234-56789."},
    {"id": "BANK-7724", "source": "Bank", "weight": 3,
     "text": "Shree Traders received ₹1,80,000 from Amit Kumar after a sequence of smaller transfers."},
    {"id": "SURV-3303", "source": "Surveillance", "weight": 3,
     "text": "Rahul Verma met Deepak Chauhan at Bihta near a vehicle BR02CD4567."},
    {"id": "SOC-1155", "source": "Social", "weight": 2,
     "text": "Vikas Rana posted a message referencing Ganga Logistics and a meeting in Muzaffarpur."},
    {"id": "FIR-2093", "source": "FIR", "weight": 2, "complainant": "Patna Police (raid)",
     "text": "Raid notes mention Sunil Yadav, Deepak Chauhan and Ganga Logistics in connection with the same network."},
    {"id": "CDR-4473", "source": "CDR", "weight": 2,
     "text": "Deepak Chauhan contacted Rahul Verma 19 times during a two-day period."},
    {"id": "BANK-7725", "source": "Bank", "weight": 2,
     "text": "NorthStar Finance Co-op received ₹95,000 linked to Vikas Rana and Amit Kumar."},
    {"id": "SURV-3304", "source": "Surveillance", "weight": 2,
     "text": "Vikas Rana was observed near Gandhi Maidan speaking with Sunil Yadav."},
    # Explicit reliability-caution scenario
    {"id": "FIR-2094", "source": "FIR", "weight": 1, "complainant": "Suresh Thakur",
     "text": "Suresh Thakur filed a complaint naming Rakesh Oza as an accomplice in an ongoing trafficking case. No phone records, financial transactions, or surveillance evidence corroborate the claim."},
    {"id": "FIR-2095", "source": "FIR", "weight": 1, "complainant": "Suresh Thakur",
     "text": "A second complaint by Suresh Thakur again names Rakesh Oza, this time in an unrelated property dispute matter, filed two weeks after the first complaint."},
]

# --------------------------------------------------------------------------
# 8. FastAPI
# --------------------------------------------------------------------------

app = FastAPI(title="VIGIL — AI Crime Network Analyzer", version="2.0-demo")
app.mount("/static", StaticFiles(directory="static"), name="static")

class LoginRequest(BaseModel):
    username: str
    password: str

class Record(BaseModel):
    id: str
    source: str
    text: str
    weight: int = 1
    complainant: Optional[str] = None

class RecordBatch(BaseModel):
    records: List[Record] = Field(min_length=1)

@app.get("/")
def home():
    return FileResponse("static/index.html")

@app.post("/api/login")
def login(req: LoginRequest):
    user = DEMO_USERS.get(req.username)
    if not user or user["password"] != req.password:
        raise HTTPException(status_code=401, detail="Invalid demo credentials")
    token = issue_token(req.username)
    identity = {
        "username": req.username,
        "role": user["role"],
        "district": user["district"],
    }
    audit("LOGIN", {"successful": True}, identity)
    return {"token": token, "user": identity}

@app.get("/api/me")
def me(user: Dict[str, str] = Depends(current_user)):
    return user

@app.get("/api/case-summary")
def case_summary(user: Dict[str, str] = Depends(current_user)):
    counts = Counter(r["source"] for r in SAMPLE_RECORDS)
    return {
        "case_id": "VIGIL-DEMO-001",
        "title": "Multi-source intelligence demonstration",
        "data_status": "Synthetic demonstration data",
        "records": len(SAMPLE_RECORDS),
        "sources": dict(counts),
        "objective": "Identify high-value network connectors, corroborate relationships, and flag unverified accusations.",
        "rbac_role": user["role"],
    }

@app.get("/api/sample-data")
def get_sample_data(user: Dict[str, str] = Depends(current_user)):
    audit("LOAD_SAMPLE_CASE", {"case_id": "VIGIL-DEMO-001"}, user)
    return {"records": SAMPLE_RECORDS}

def normalize_records(batch: RecordBatch) -> List[Dict[str, Any]]:
    out = []
    for r in batch.records:
        ents = extract_entities(r.text)
        out.append({
            "id": r.id,
            "source": r.source,
            "text": r.text,
            "weight": r.weight,
            "complainant": r.complainant,
            "entities": ents,
        })
    return out

@app.post("/api/extract")
def api_extract(batch: RecordBatch, user: Dict[str, str] = Depends(current_user)):
    out = normalize_records(batch)
    counts = Counter(e["type"] for r in out for e in r["entities"])
    audit("EXTRACT_ENTITIES", {"records": len(out), "entity_counts": dict(counts)}, user)
    return {"records": out, "entity_counts": dict(counts)}

@app.post("/api/analyze")
def api_analyze(batch: RecordBatch, user: Dict[str, str] = Depends(current_user)):
    records = normalize_records(batch)
    G = build_graph(records)
    analytics = run_analytics(G)
    alerts = detect_alerts(records, G, analytics)
    record_source_map = {r["id"]: r["source"] for r in records}

    nodes = []
    for n in G.nodes:
        recs = list(G.nodes[n]["records"])
        sources = sorted({record_source_map[rid] for rid in recs})
        influence = analytics["influence"][n]
        role = (
            "Broker / Bridge"
            if n in analytics["articulation_points"]
            else "Network Hub"
            if G.degree(n) >= 4
            else "Connected Entity"
        )
        nodes.append({
            "id": n,
            "type": G.nodes[n]["type"],
            "degree": G.degree(n),
            "records": recs,
            "source_types": sources,
            "betweenness": round(analytics["betweenness_centrality"][n], 4),
            "influence": influence,
            "community": analytics["community_of"].get(n, -1),
            "is_bridge": n in analytics["articulation_points"],
            "corroborated": bool(set(sources) - {"FIR"}),
            "role": role,
        })

    links = []
    for u, v in G.edges():
        data = G[u][v]
        links.append({
            "source": u,
            "target": v,
            "weight": data["weight"],
            "records": data["records"],
            "confidence": data["confidence"],
            "evidence_status": data["evidence_status"],
            "source_types": sorted(data["source_types"]),
        })

    ranked = sorted(nodes, key=lambda x: x["influence"], reverse=True)[:5]
    entity_counts = Counter(e["type"] for r in records for e in r["entities"])

    audit("RUN_ANALYSIS", {
        "records": len(records),
        "nodes": len(nodes),
        "links": len(links),
        "alerts": len(alerts),
    }, user)

    return {
        "records": records,
        "nodes": nodes,
        "links": links,
        "num_communities": analytics["num_communities"],
        "top_influencers": ranked,
        "alerts": alerts,
        "entity_counts": dict(entity_counts),
        "pipeline": [
            "Ingest intelligence",
            "Extract entities",
            "Build weighted graph",
            "Run graph analytics",
            "Check corroboration",
            "Generate explainable alerts",
        ],
    }

@app.get("/api/audit")
def get_audit(
    limit: int = Query(default=50, ge=1, le=500),
    user: Dict[str, str] = Depends(require_role("DISTRICT_ADMIN")),
):
    return {"records": list(reversed(AUDIT_LOG[-limit:]))}

@app.get("/api/audit/verify")
def audit_verify(
    user: Dict[str, str] = Depends(require_role("DISTRICT_ADMIN")),
):
    return verify_audit_chain()

class EncryptRequest(BaseModel):
    value: str

@app.post("/api/security/encrypt-demo")
def encrypt_demo(req: EncryptRequest, user: Dict[str, str] = Depends(require_role("DISTRICT_ADMIN"))):
    encrypted = encrypt_value(req.value)
    audit("ENCRYPT_DEMO_VALUE", {"length": len(req.value)}, user)
    return {"encrypted": encrypted}

@app.post("/api/security/decrypt-demo")
def decrypt_demo(req: EncryptRequest, user: Dict[str, str] = Depends(require_role("DISTRICT_ADMIN"))):
    return {"decrypted": decrypt_value(req.value)}

@app.get("/api/security/status")
def security_status(user: Dict[str, str] = Depends(current_user)):
    audit_status = verify_audit_chain()
    return {
        "rbac": True,
        "audit_hash_chain": audit_status,
        "encryption_helper": True,
        "data_mode": "SYNTHETIC",
        "neo4j": False,
        "multilingual_ner": False,
        "trained_anomaly_model": False,
    }
