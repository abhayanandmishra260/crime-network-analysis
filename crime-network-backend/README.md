# VIGIL — AI Crime Network Analyzer (Python Backend)

SIH prototype for: **AI-powered system to uncover hidden criminal networks
from FIRs, CDRs, financial records, surveillance and social media
intelligence.**

## What's real vs. simulated in this prototype

| Component | Status |
|---|---|
| Entity extraction (people, locations, phones, vehicles, orgs) | **Real spaCy NER** (`en_core_web_sm`) + custom `EntityRuler` + regex |
| Relationship graph construction | **Real NetworkX** weighted co-occurrence graph |
| Degree centrality / betweenness centrality | **Real NetworkX** algorithms |
| Community detection (which "cluster" an entity belongs to) | **Real NetworkX** (`greedy_modularity_communities`) |
| Key-influencer / broker detection | **Real** articulation points + betweenness centrality |
| Suspicious pattern alerts | Rule-based (keyword + graph structure) — placeholder for a trained anomaly-detection model |
| Sample data (FIR/CDR/Bank/Social/Surveillance records) | Synthetic demo data, mirrors real-world formats |

## Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

## Run

```bash
uvicorn main:app --reload
```

Open **http://127.0.0.1:8000** in your browser. Click through the 4 pipeline
steps on the left (Ingest → Extract → Build Graph → Run Analytics) to see
the network form and the AI-generated insights appear on the right.

## API endpoints (usable independently of the UI)

- `GET /api/sample-data` — returns the demo intelligence records
- `POST /api/extract` — body: `{"records":[{"id":"...","source":"...","text":"...","weight":1}]}` → returns entities per record (spaCy NER)
- `POST /api/analyze` — same input → full pipeline output: `nodes`, `links`, `top_influencers`, `alerts`, `num_communities`

Try it directly:

```bash
curl -s http://127.0.0.1:8000/api/sample-data | python -m json.tool
```

## Extending this to a real deployment

1. Swap `en_core_web_sm` + `EntityRuler` for a fine-tuned transformer NER
   model trained on labelled FIR/CDR text (Hindi + English, e.g. via
   HuggingFace + IndicNLP for regional languages).
2. Replace the in-memory NetworkX graph with **Neo4j** for persistence at
   scale, using Cypher queries for the same centrality/community algorithms
   (Neo4j Graph Data Science library has native implementations).
3. Replace the rule-based `detect_alerts()` with a trained anomaly-detection
   model (e.g. isolation forest on transaction/call metadata).
4. Add authentication + role-based access control before connecting to any
   real law-enforcement data source — this prototype has none, by design,
   since it only ever touches synthetic demo data.
