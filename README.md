# TrustGraph - Cyber Intelligence Command

A cinematic Streamlit dashboard for graph-based fraud ring and wash-trading surveillance.

## Features
- Command Overview: KPI cards, risk timeline, live threat feed, top-risk users
- Shared Infrastructure: telemetry ingestion, risk score, explainability chain, live entity topology map
- Circular Wash-Trading: closed-loop transaction detection with directed graph
- Threat Hunt Console: blast-radius analysis from any entity
- Audit Log and Export: filterable tables with CSV download
- Executive Incident Brief: auto-generated report, downloadable as text
- Offline mode: local simulation engine when the backend API is unreachable

## Tech stack
Python, Streamlit, PyVis, pandas, requests

## Run
```
pip install -r requirements.txt
streamlit run trustgraph_app.py
```
Backend is expected at http://127.0.0.1:8000 by default. It can be changed in the sidebar.

## Backend endpoints
- GET / : health check
- POST /events/ingest : telemetry risk evaluation
- POST /transactions/ingest : transaction ingestion and loop scan
- GET /transactions/analysis/cycles : active cycle report

## Notes
Local simulation scores are a demo heuristic, not production risk scoring. Validate findings against backend data.
