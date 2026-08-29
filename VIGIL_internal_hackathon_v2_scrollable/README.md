# VIGIL — Internal Hackathon Prototype v2

This package is a drop-in demo upgrade for the existing SIH prototype.

## What was added

- Demo RBAC: INVESTIGATOR / DISTRICT_ADMIN / STATE_ADMIN
- SHA-256 hash-chained audit log
- Audit-chain verification endpoint
- Fernet encryption helper endpoints
- Structured evidence metadata on nodes, links and alerts
- One-click `RUN FULL INVESTIGATION`
- Investigator-style dashboard
- Evidence coverage
- Verified vs single-source relationship filters
- Key-player investigator profiles
- Alert-to-entity navigation
- Explicit prototype/roadmap status for Neo4j, multilingual NER and ML anomaly detection

## Demo credentials

All demo users use password `vigil123`.

- investigator
- district_admin
- state_admin

The dashboard can also read the synthetic demo case anonymously for convenience; login is available from **Switch user** and is used for audit events and privileged audit APIs.

## Run

```bash
python -m venv venv
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

pip install -r requirements.txt
python -m spacy download en_core_web_sm

uvicorn main:app --reload
```

Open:
http://127.0.0.1:8000

## Judge demo flow

1. Run Full Investigation.
2. Show entity extraction and source counts.
3. Show the network graph.
4. Click the highest-influence player.
5. Show source coverage and linked evidence.
6. Open Alerts.
7. Open the Rakesh Oza reliability caution.
8. Switch to district_admin and show:
   `✓ HASH CHAIN VALID`
9. Explain roadmap:
   Neo4j / multilingual NER / trained anomaly detection.

## Important

This is still synthetic data and demo-grade security. Do not connect it directly to real law-enforcement data without proper identity management, key management, encrypted storage, TLS, auditing persistence, data governance, testing, and authorization controls.
