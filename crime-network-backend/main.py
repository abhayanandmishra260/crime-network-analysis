"""
VIGIL — AI Crime Network Analyzer
Python backend (FastAPI + spaCy + NetworkX)

Pipeline:
  1. Ingest records (FIR / CDR / Bank / Social Media / Surveillance)
  2. Extract entities using spaCy NER + a custom EntityRuler (people, locations,
     organizations) plus regex extractors for phone numbers and vehicle numbers
  3. Build a weighted co-occurrence graph with NetworkX
  4. Run graph analytics: degree centrality, betweenness centrality,
     community detection, articulation points (bridge / broker identification)
  5. Rule-based suspicious pattern detection over the raw text + graph structure

Run:
    pip install -r requirements.txt
    python -m spacy download en_core_web_sm   # or install the wheel directly
    uvicorn main:app --reload
Then open http://127.0.0.1:8000
"""

import re
from typing import List, Dict, Any
from collections import defaultdict

import networkx as nx
import spacy
from spacy.pipeline import EntityRuler
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

# --------------------------------------------------------------------------
# 1. NLP PIPELINE SETUP
# --------------------------------------------------------------------------
nlp = spacy.load("en_core_web_sm")

# Known entity dictionaries used to seed the EntityRuler so the demo is
# reliable even on a small general-purpose model. In production this ruler
# would be replaced / supplemented by a fine-tuned transformer NER model
# trained on labelled FIR / CDR text (including Hindi via IndicNLP / HuggingFace).
KNOWN_PERSONS = ["Rahul Verma", "Sunil Yadav", "Amit Kumar", "Priya Singh",
                  "Vikas Rana", "Deepak Chauhan", "Meena Devi", "Suresh Thakur",
                  "Anil Mishra", "Rakesh Oza"]
KNOWN_LOCATIONS = ["Gandhi Maidan, Patna", "Gandhi Maidan", "Patna", "Danapur",
                     "Kankarbagh", "Bihta", "Muzaffarpur"]
KNOWN_ORGS = ["Shree Traders", "Ganga Logistics", "NorthStar Finance Co-op"]

ruler = nlp.add_pipe("entity_ruler", before="ner")
patterns = []
for p in KNOWN_PERSONS:
    patterns.append({"label": "PERSON", "pattern": p})
for l in KNOWN_LOCATIONS:
    patterns.append({"label": "GPE", "pattern": l})
for o in KNOWN_ORGS:
    patterns.append({"label": "ORG", "pattern": o})
ruler.add_patterns(patterns)

PHONE_RE = re.compile(r"\+91-\d{5}-\d{5}")
VEHICLE_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z]{2}\d{3,4}\b")
AMOUNT_RE = re.compile(r"₹\s?[\d,]+")

LABEL_MAP = {"PERSON": "person", "GPE": "location", "LOC": "location", "ORG": "org"}


def extract_entities(text: str) -> List[Dict[str, str]]:
    """Run spaCy NER + EntityRuler + regex extractors, return deduped entity list."""
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
# 2. GRAPH CONSTRUCTION
# --------------------------------------------------------------------------
def build_graph(records: List[Dict[str, Any]]) -> nx.Graph:
    """Co-occurrence graph: two entities get an edge (weighted) whenever they
    appear together in the same intelligence record. Weight accumulates with
    every additional shared record and the record's own severity weight.

    Each edge also tracks WHICH SOURCE TYPES (FIR / CDR / Bank / Social /
    Surveillance) support it. This is the basis of the confidence-scoring
    layer: an edge is only "verified" once it is corroborated by 2+
    INDEPENDENT source types. A single FIR — even several FIRs from the
    same complainant — is not, by itself, enough. This directly guards
    against a fabricated or malicious FIR being treated as equivalent to
    corroborated evidence like call records or bank transactions."""
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
                    G.add_edge(a, b, weight=w, records=[r["id"]],
                               source_types={r["source"]})

    for u, v in G.edges():
        G[u][v]["confidence"] = "verified" if len(G[u][v]["source_types"]) >= 2 else "unverified"

    return G


# --------------------------------------------------------------------------
# 3. GRAPH ANALYTICS
# --------------------------------------------------------------------------
def run_analytics(G: nx.Graph) -> Dict[str, Any]:
    degree_c = nx.degree_centrality(G)
    between_c = nx.betweenness_centrality(G, weight=None, normalized=True)

    max_deg = max(degree_c.values()) if degree_c else 1
    max_bet = max(between_c.values()) if between_c else 1

    influence = {
        n: round(0.5 * (degree_c[n] / max_deg if max_deg else 0)
                  + 0.5 * (between_c[n] / max_bet if max_bet else 0), 4)
        for n in G.nodes
    }

    # Community detection -> which "cluster" each entity belongs to
    communities = list(nx.algorithms.community.greedy_modularity_communities(G, weight="weight"))
    community_of = {}
    for idx, c in enumerate(communities):
        for n in c:
            community_of[n] = idx

    # Articulation points = real cut-vertices. Removing them splits the network.
    # These are the strongest "broker / middleman" candidates.
    articulation = list(nx.articulation_points(G)) if nx.is_connected(G) or G.number_of_nodes() else []
    if not nx.is_connected(G):
        articulation = []
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
# 4. RULE-BASED SUSPICIOUS PATTERN DETECTION
# --------------------------------------------------------------------------
def detect_alerts(records: List[Dict[str, Any]], G: nx.Graph, analytics: Dict[str, Any]) -> List[Dict[str, str]]:
    alerts = []

    # (a) High-frequency contact — look for call-count mentions in CDR text
    for r in records:
        if r["source"] == "CDR":
            m = re.search(r"(\d+)\s+times", r["text"])
            if m and int(m.group(1)) >= 15:
                alerts.append({
                    "title": "Unusual call frequency",
                    "severity": "lead",
                    "text": f"{r['id']}: {m.group(1)} contacts recorded — well above normal contact frequency. Indicates active coordination rather than casual contact.",
                })

    # (b) Structured transactions (smurfing) — bank records mentioning a split
    for r in records:
        if r["source"] == "Bank" and ("split" in r["text"].lower() or "transactions to avoid" in r["text"].lower()):
            amt = AMOUNT_RE.search(r["text"])
            alerts.append({
                "title": "Possible structuring (smurfing)",
                "severity": "lead",
                "text": f"{r['id']}: transaction {amt.group(0) if amt else ''} broken into multiple parts — a pattern typically used to stay under mandatory reporting thresholds.",
            })

    # (c) Cluster-bridging entities. True cut-vertices (articulation points) are the
    # strongest signal; if the graph is dense enough that none exist, fall back to
    # the highest betweenness-centrality node — the entity that sits on the most
    # shortest paths between other entities, i.e. the most likely broker.
    aps = sorted(analytics["articulation_points"],
                 key=lambda n: analytics["influence"].get(n, 0), reverse=True)
    if aps:
        for n in aps[:2]:
            alerts.append({
                "title": "Cluster-bridging entity detected",
                "severity": "lead",
                "text": f"'{n}' is a cut-vertex: removing it would split the network into disconnected clusters. This is a strong signal of a broker / middleman role — flag as a priority investigation target.",
            })
    else:
        top_bridge = max(analytics["betweenness_centrality"],
                          key=analytics["betweenness_centrality"].get)
        alerts.append({
            "title": "Cluster-bridging entity detected",
            "severity": "lead",
            "text": f"'{top_bridge}' has the highest betweenness centrality in the network — it sits on more shortest paths between other entities than anyone else, consistent with a broker / middleman role. Flag as a priority investigation target.",
        })

    # (d) Cross-community edges = unexplained links between otherwise separate groups.
    # Rank by combined influence of the two endpoints and keep only the strongest few,
    # otherwise a dense demo graph produces a noisy alert list.
    com = analytics["community_of"]
    cross_pairs = []
    seen_pairs = set()
    for u, v in G.edges():
        if com.get(u) != com.get(v):
            pair = tuple(sorted([u, v]))
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                score = analytics["influence"].get(u, 0) + analytics["influence"].get(v, 0)
                cross_pairs.append((score, u, v))
    cross_pairs.sort(reverse=True)
    for score, u, v in cross_pairs[:3]:
        alerts.append({
            "title": "Unexplained cross-cluster link",
            "severity": "lead",
            "text": f"'{u}' and '{v}' belong to otherwise separate clusters but are directly linked — possible hand-off point between two operations.",
        })

    # (e) UNCORROBORATED ACCUSATIONS — guards against a fabricated or mistaken
    # FIR being treated as equivalent to real evidence. A person is flagged
    # here only if EVERY record that mentions them is a FIR (i.e. nothing —
    # no CDR, bank record, surveillance log, or social intelligence —
    # independently substantiates their presence in the network at all).
    # This is a caution, not a lead: it tells the investigator "don't trust
    # this connection yet", the opposite of every other alert above.
    record_source = {r["id"]: r["source"] for r in records}
    accused_by = defaultdict(set)  # entity -> {complainant names}
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
            alerts.append({
                "title": "Uncorroborated accusation — needs verification",
                "severity": "caution",
                "text": f"'{person}' is named only in FIR complaint(s) filed by {', '.join(sorted(complainants))}. No independent evidence (CDR, bank records, surveillance, or social intelligence) corroborates this connection. Treat as an unverified lead, not a confirmed link, until cross-checked.",
            })

    # (f) POSSIBLE MALICIOUS COMPLAINT PATTERN — same complainant repeatedly
    # naming the same person across multiple FIRs with zero corroboration
    # from any independent source. This is exactly the "fake FIR to frame
    # someone" scenario — the system surfaces it as a red flag on the
    # COMPLAINANT, not the accused, so the investigator checks motive/history
    # before acting on the accusation.
    pair_counts = defaultdict(list)
    for r in records:
        complainant = r.get("complainant")
        if r["source"] == "FIR" and complainant:
            for e in r["entities"]:
                if e["text"] != complainant and e["type"] == "person":
                    pair_counts[(complainant, e["text"])].append(r["id"])

    for (complainant, accused), record_ids in pair_counts.items():
        source_types_seen = {record_source[rid] for rid in G.nodes[accused]["records"]} if accused in G else set()
        corroborated_elsewhere = bool(source_types_seen - {"FIR"})
        if len(record_ids) >= 2 and not corroborated_elsewhere:
            alerts.append({
                "title": "Possible malicious complaint pattern",
                "severity": "caution",
                "text": f"'{complainant}' has filed {len(record_ids)} separate FIRs ({', '.join(record_ids)}) naming '{accused}', with no corroborating evidence from any independent source. Recommend reviewing the complainant's history and possible motive before treating '{accused}' as a suspect.",
            })

    return alerts


# --------------------------------------------------------------------------
# 5. SAMPLE DATA (stand-in for real FIR / CDR / Bank / Social feeds)
# --------------------------------------------------------------------------
SAMPLE_RECORDS = [
    {"id": "FIR-2091", "source": "FIR", "weight": 3, "complainant": "Patna Police (raid)",
     "text": "Complaint filed against Rahul Verma and Sunil Yadav for possession of contraband recovered near Gandhi Maidan, Patna. Vehicle BR01AB1234 was used to transport the material."},
    {"id": "CDR-4471", "source": "CDR", "weight": 5,
     "text": "Call Detail Record: number +91-98350-11223 (Rahul Verma) contacted +91-97011-44556 (Sunil Yadav) 47 times over 6 days, mostly between 11 PM and 2 AM."},
    {"id": "BANK-7723", "source": "Bank", "weight": 4,
     "text": "Transaction alert: ₹4,80,000 transferred from Sunil Yadav's account to Amit Kumar's account via NorthStar Finance Co-op, split into 6 transactions to avoid reporting threshold."},
    {"id": "FIR-2092", "source": "FIR", "weight": 2, "complainant": "Patna Police (raid)",
     "text": "Vikas Rana named as co-accused with Sunil Yadav in the same case, last known address in Danapur."},
    {"id": "SURV-3301", "source": "Surveillance", "weight": 3,
     "text": "Surveillance team observed Vikas Rana and Deepak Chauhan meeting near Kankarbagh warehouse belonging to Ganga Logistics on three separate occasions."},
    {"id": "SOC-8890", "source": "Social", "weight": 2,
     "text": "Social media intelligence: Deepak Chauhan and Meena Devi tagged in the same photo at an event in Bihta, geolocation confirmed."},
    {"id": "BANK-7724", "source": "Bank", "weight": 3,
     "text": "Amit Kumar's firm Shree Traders received a payment of ₹6,20,000 from Priya Singh, invoice description flagged as inconsistent with declared business activity."},
    {"id": "CDR-4472", "source": "CDR", "weight": 3,
     "text": "Priya Singh's number +91-99312-77889 shows repeated contact with Suresh Thakur's number +91-90123-45678, concentrated around dates of large bank transfers."},
    {"id": "FIR-2093", "source": "FIR", "weight": 2, "complainant": "Patna Police (raid)",
     "text": "Suresh Thakur previously named in an economic offences case linked to Anil Mishra, both associated with NorthStar Finance Co-op."},
    {"id": "SURV-3302", "source": "Surveillance", "weight": 4,
     "text": "Anil Mishra seen meeting Sunil Yadav at Ganga Logistics warehouse in Kankarbagh, believed to be a hand-off point between the two clusters."},
    {"id": "CDR-4473", "source": "CDR", "weight": 3,
     "text": "Sunil Yadav's number +91-97011-44556 called Anil Mishra 12 times within 48 hours preceding the warehouse meeting."},
    {"id": "SOC-8891", "source": "Social", "weight": 2,
     "text": "Meena Devi and Vikas Rana both commented on a public post referencing Gandhi Maidan, Patna on the same day as the FIR-2091 incident."},
    {"id": "BANK-7725", "source": "Bank", "weight": 2,
     "text": "Vehicle BR06CD5678 registered under Deepak Chauhan was used to collect a cash consignment near Bihta, cross-referenced with Ganga Logistics dispatch logs."},

    # ---- Fabricated / uncorroborated accusation scenario (demo) ----
    # Suresh Thakur (a real network participant with a grudge) files two FIRs
    # naming an otherwise unconnected person, Rakesh Oza, with zero supporting
    # evidence from any other source. This is exactly the "fake FIR" case:
    # the system should NOT let this look equivalent to a corroborated link.
    {"id": "FIR-2094", "source": "FIR", "weight": 1, "complainant": "Suresh Thakur",
     "text": "Suresh Thakur filed a complaint naming Rakesh Oza as an accomplice in an ongoing trafficking case. No phone records, financial transactions, or surveillance evidence corroborate the claim."},
    {"id": "FIR-2095", "source": "FIR", "weight": 1, "complainant": "Suresh Thakur",
     "text": "A second complaint by Suresh Thakur again names Rakesh Oza, this time in an unrelated property dispute matter, filed two weeks after the first complaint."},
]


# --------------------------------------------------------------------------
# 6. FASTAPI APP
# --------------------------------------------------------------------------
app = FastAPI(title="VIGIL — AI Crime Network Analyzer")


class Record(BaseModel):
    id: str
    source: str
    text: str
    weight: int = 1
    complainant: str | None = None


class RecordBatch(BaseModel):
    records: List[Record]


@app.get("/api/sample-data")
def get_sample_data():
    return {"records": SAMPLE_RECORDS}


@app.post("/api/extract")
def api_extract(batch: RecordBatch):
    """Step 2: run real spaCy NER + regex extraction on submitted records."""
    out = []
    for r in batch.records:
        ents = extract_entities(r.text)
        out.append({"id": r.id, "source": r.source, "text": r.text,
                     "weight": r.weight, "complainant": r.complainant, "entities": ents})
    return {"records": out}


@app.post("/api/analyze")
def api_analyze(batch: RecordBatch):
    """Full pipeline: extract -> build graph -> analytics -> alerts.
    Returns everything the frontend needs to render the network + insights."""
    records_with_entities = []
    for r in batch.records:
        ents = extract_entities(r.text)
        records_with_entities.append({"id": r.id, "source": r.source, "text": r.text,
                                        "weight": r.weight, "complainant": r.complainant,
                                        "entities": ents})

    G = build_graph(records_with_entities)
    analytics = run_analytics(G)
    alerts = detect_alerts(records_with_entities, G, analytics)

    record_source_map = {r["id"]: r["source"] for r in records_with_entities}
    nodes = [{
        "id": n,
        "type": G.nodes[n]["type"],
        "degree": G.degree(n),
        "records": list(G.nodes[n]["records"]),
        "betweenness": round(analytics["betweenness_centrality"][n], 4),
        "influence": analytics["influence"][n],
        "community": analytics["community_of"].get(n, -1),
        "is_bridge": n in analytics["articulation_points"],
        "corroborated": bool({record_source_map[rid] for rid in G.nodes[n]["records"]} - {"FIR"}),
    } for n in G.nodes]

    links = [{
        "source": u, "target": v,
        "weight": G[u][v]["weight"],
        "records": G[u][v]["records"],
        "confidence": G[u][v]["confidence"],
        "source_types": sorted(G[u][v]["source_types"]),
    } for u, v in G.edges()]

    ranked = sorted(nodes, key=lambda x: x["influence"], reverse=True)[:5]

    return {
        "records": records_with_entities,
        "nodes": nodes,
        "links": links,
        "num_communities": analytics["num_communities"],
        "top_influencers": ranked,
        "alerts": alerts,
    }


# Serve the frontend
app.mount("/", StaticFiles(directory="static", html=True), name="static")
