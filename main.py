from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import networkx as nx
from typing import List, Optional, Dict, Any

app = FastAPI(
    title="TrustGraph Enterprise Fraud Analytics API",
    description="High-performance graph intelligence engine for shared infrastructure threat detection and circular wash-trading discovery.",
    version="2.1.0"
)

class EventPayload(BaseModel):
    user_id: str = Field(..., description="Unique user identifier")
    device_id: str = Field(..., description="Hardware/device fingerprint ID")
    ip_address: str = Field(..., description="IPv4 or IPv6 network address")
    action: Optional[str] = Field("LOGIN", description="Associated telemetry action type")

class TransactionPayload(BaseModel):
    sender: str = Field(..., description="Source account identifier")
    receiver: str = Field(..., description="Destination account identifier")
    amount: float = Field(..., gt=0.0, description="Transaction volume in USD")
    timestamp: str = Field(..., description="ISO-8601 formatted timestamp")

class TrustGraphEngine:
    def __init__(self):
        self.entity_graph = nx.Graph()
        self.tx_graph = nx.DiGraph()

    def add_entity_event(self, event: EventPayload):
        self.entity_graph.add_node(event.user_id, type="User")
        self.entity_graph.add_node(event.device_id, type="Device")
        self.entity_graph.add_node(event.ip_address, type="IP")
        self.entity_graph.add_edge(event.user_id, event.device_id, relationship="USED_DEVICE", action=event.action)
        self.entity_graph.add_edge(event.device_id, event.ip_address, relationship="CONNECTED_VIA")

    def add_transaction(self, tx: TransactionPayload):
        self.tx_graph.add_node(tx.sender, type="User")
        self.tx_graph.add_node(tx.receiver, type="User")
        self.tx_graph.add_edge(tx.sender, tx.receiver, amount=tx.amount, timestamp=tx.timestamp)

    def evaluate_user_risk(self, user_id: str, max_allowed_users_per_device: int = 2) -> Dict[str, Any]:
        if user_id not in self.entity_graph:
            return {
                "user_id": user_id,
                "entity_risk_score": 0.0,
                "risk_status": "LOW_RISK",
                "explainability_payload": {
                    "cluster_users": [user_id],
                    "flagged_devices": [],
                    "reasoning_chain": ["User initialized in network graph. No prior shared infrastructure anomalies detected."]
                }
            }

        component = nx.node_connected_component(self.entity_graph, user_id)
        subgraph = self.entity_graph.subgraph(component)

        users = [n for n, d in subgraph.nodes(data=True) if d.get("type") == "User"]
        devices = [n for n, d in subgraph.nodes(data=True) if d.get("type") == "Device"]

        risk_score = 0.0
        reasons = []
        flagged_devices = []

        for dev in devices:
            connected_users = [nbr for nbr in self.entity_graph.neighbors(dev) if self.entity_graph.nodes[nbr].get("type") == "User"]
            if len(connected_users) > max_allowed_users_per_device:
                flagged_devices.append(dev)
                excess_ratio = len(connected_users) / max_allowed_users_per_device
                risk_score += 0.5 * min(excess_ratio, 1.0)
                reasons.append(
                    f"Shared Infrastructure Alert: Device '{dev}' is linked to {len(connected_users)} distinct users "
                    f"({', '.join(connected_users)}), exceeding threshold of {max_allowed_users_per_device}."
                )

        risk_score = min(round(risk_score, 2), 1.0)
        status = "HIGH_RISK" if risk_score >= 0.7 else ("MEDIUM_RISK" if risk_score >= 0.3 else "LOW_RISK")

        return {
            "user_id": user_id,
            "entity_risk_score": risk_score,
            "risk_status": status,
            "explainability_payload": {
                "cluster_users": users,
                "flagged_devices": flagged_devices,
                "reasoning_chain": reasons if reasons else ["Entity operates within normal baseline security parameters."]
            }
        }

    def detect_wash_trading_cycles(self, max_cycle_length: int = 5, min_volume: float = 1000.0) -> List[Dict[str, Any]]:
        alerts = []
        try:
            for cycle in nx.simple_cycles(self.tx_graph):
                if 2 < len(cycle) <= max_cycle_length:
                    cycle_path_closed = cycle + [cycle[0]]
                    total_recycled_volume = 0.0
                    transaction_trail = []
                    valid_cycle = True

                    for i in range(len(cycle)):
                        u = cycle[i]
                        v = cycle[(i + 1) % len(cycle)]
                        edge_data = self.tx_graph.get_edge_data(u, v)

                        if edge_data:
                            amt = edge_data.get("amount", 0.0)
                            total_recycled_volume += amt
                            transaction_trail.append({
                                "sender": u,
                                "receiver": v,
                                "amount": amt,
                                "timestamp": edge_data.get("timestamp")
                            })
                        else:
                            valid_cycle = False
                            break

                    if valid_cycle and total_recycled_volume >= min_volume:
                        alerts.append({
                            "alert_type": "CIRCULAR_WASH_TRADING_DETECTED",
                            "severity": "HIGH",
                            "involved_accounts": cycle,
                            "cycle_path": " -> ".join(cycle_path_closed),
                            "total_recycled_volume": total_recycled_volume,
                            "explainability_payload": {
                                "hop_count": len(cycle),
                                "reasoning": f"Detected closed-loop transaction cycle involving accounts ({', '.join(cycle)}). Total recycled volume: ${total_recycled_volume:,.2f}.",
                                "transaction_trail": transaction_trail
                            }
                        })
        except Exception as e:
            print(f"Cycle detection error: {e}")
        return alerts

engine = TrustGraphEngine()

@app.get("/")
def read_root():
    return {"status": "ONLINE", "system": "TrustGraph Engine", "docs": "/docs"}

@app.post("/events/ingest")
def ingest_event(event: EventPayload):
    engine.add_entity_event(event)
    assessment = engine.evaluate_user_risk(event.user_id)
    return {"status": "SUCCESS", "message": "Telemetry event successfully ingested.", "assessment": assessment}

@app.get("/risk/{user_id}")
def get_user_risk(user_id: str):
    return engine.evaluate_user_risk(user_id)

@app.post("/transactions/ingest")
def ingest_transaction(tx: TransactionPayload):
    engine.add_transaction(tx)
    active_cycles = engine.detect_wash_trading_cycles()
    involved_in_cycle = any(tx.sender in cycle["involved_accounts"] for cycle in active_cycles)
    return {
        "status": "SUCCESS",
        "message": "Transaction recorded and evaluated against temporal transaction ledger.",
        "transaction": tx.model_dump(),
        "flagged_wash_trading": involved_in_cycle,
        "active_cycle_alerts": active_cycles
    }

@app.get("/transactions/analysis/cycles")
def get_wash_trading_reports():
    alerts = engine.detect_wash_trading_cycles()
    return {
        "total_active_cycles": len(alerts),
        "alerts": alerts
    }