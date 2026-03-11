"""
Modular Flask app wiring using cloud scaffolding.
Enhanced with modern features: stats, agents, threats, export, signatures.
"""
from __future__ import annotations
import time
import json
from collections import defaultdict
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, send_file
from flask_socketio import SocketIO, emit
from cloud.schemas import IngestBatch
from cloud.ingestion.queue import InMemoryQueue
from typing import Dict, List, Any


def create_app(queue=None):
    app = Flask(__name__)
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
    q = queue or InMemoryQueue()
    start_time = time.time()
    
    # In-memory stats (in production, use database)
    stats = {
        "total_events": 0,
        "total_alerts": 0,
        "unique_agents": set(),
        "events_by_hour": defaultdict(int),
        "alerts_by_hour": defaultdict(int),
        "recent_events": [],
        "agent_activity": defaultdict(lambda: {"last_seen": None, "event_count": 0, "alert_count": 0}),
        "threat_intel": [],
        "top_threats": defaultdict(int)
    }
    
    signatures = []

    @app.route("/")
    def index():
        return render_template("index.html")
    
    @app.route("/ui")
    def ui():
        return render_template("index.html")

    @app.route("/health")
    def health():
        return jsonify({
            "status": "ok",
            "uptime_sec": round(time.time() - start_time, 1),
            "queue_size": len(q._queue) if hasattr(q, "_queue") else 0
        })

    @app.route("/analyze", methods=["POST"])
    def analyze():
        """Main ingestion endpoint - processes events and emits via socketio"""
        try:
            data = request.get_json(force=True)
            events = data if isinstance(data, list) else [data]
            
            for evt_raw in events:
                try:
                    batch = IngestBatch(events=[evt_raw])
                    evt = batch.events[0].dict()
                    q.put(evt)
                    
                    # Update stats
                    stats["total_events"] += 1
                    if evt.get("alert"):
                        stats["total_alerts"] += 1
                        reason = evt.get("reason", "Unknown")
                        stats["top_threats"][reason] += 1
                    
                    agent_id = evt.get("agent_id", "unknown")
                    stats["unique_agents"].add(agent_id)
                    stats["agent_activity"][agent_id]["last_seen"] = time.time()
                    stats["agent_activity"][agent_id]["event_count"] += 1
                    if evt.get("alert"):
                        stats["agent_activity"][agent_id]["alert_count"] += 1
                    
                    hour_key = datetime.now().strftime("%Y-%m-%d %H:00")
                    stats["events_by_hour"][hour_key] += 1
                    if evt.get("alert"):
                        stats["alerts_by_hour"][hour_key] += 1
                    
                    # Keep recent events (last 1000)
                    stats["recent_events"].append(evt)
                    if len(stats["recent_events"]) > 1000:
                        stats["recent_events"].pop(0)
                    
                    # Emit real-time event
                    socketio.emit("new_event", evt)
                    
                    # Emit alert notification
                    if evt.get("alert"):
                        socketio.emit("alert_notification", {
                            "agent_id": agent_id,
                            "host": evt.get("host", "unknown"),
                            "dst_ip": evt.get("dst_ip", "unknown"),
                            "reason": evt.get("reason", "Malicious activity detected"),
                            "timestamp": evt.get("timestamp", datetime.utcnow().isoformat() + "Z")
                        })
                        
                except Exception as e:
                    print(f"Error processing event: {e}")
                    continue
            
            socketio.emit("ingest_ack", {"count": len(events), "ts": time.time()})
            return jsonify({"status": "processed", "count": len(events)}), 200
            
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    @app.route("/stats")
    def get_stats():
        """Get aggregated statistics"""
        return jsonify({
            "total_events": stats["total_events"],
            "total_alerts": stats["total_alerts"],
            "unique_agents": len(stats["unique_agents"]),
            "events_by_hour": dict(stats["events_by_hour"]),
            "alerts_by_hour": dict(stats["alerts_by_hour"]),
            "top_threats": dict(sorted(stats["top_threats"].items(), key=lambda x: x[1], reverse=True)[:10]),
            "agent_summary": {
                aid: {
                    "last_seen": act["last_seen"],
                    "event_count": act["event_count"],
                    "alert_count": act["alert_count"]
                }
                for aid, act in list(stats["agent_activity"].items())[:50]
            }
        })

    @app.route("/api/agents")
    def get_agents():
        """Get all active agents"""
        agents = []
        for agent_id, activity in stats["agent_activity"].items():
            agents.append({
                "agent_id": agent_id,
                "last_seen": activity["last_seen"],
                "event_count": activity["event_count"],
                "alert_count": activity["alert_count"],
                "status": "active" if (time.time() - activity["last_seen"]) < 300 else "inactive"
            })
        return jsonify(sorted(agents, key=lambda x: x["last_seen"] or 0, reverse=True))

    @app.route("/api/threats")
    def get_threats():
        """Get threat intelligence feed"""
        threats = []
        for reason, count in sorted(stats["top_threats"].items(), key=lambda x: x[1], reverse=True)[:20]:
            threats.append({
                "threat": reason,
                "count": count,
                "severity": "high" if count > 10 else "medium" if count > 5 else "low"
            })
        return jsonify(threats)

    @app.route("/api/signatures", methods=["GET"])
    def list_signatures():
        """List all signatures"""
        return jsonify(signatures)

    @app.route("/api/add_signature", methods=["POST"])
    def add_signature():
        """Add a new signature"""
        data = request.get_json()
        sig = {
            "id": len(signatures) + 1,
            "name": data.get("name", "Unnamed"),
            "rule": data.get("rule", ""),
            "severity": data.get("severity", "Low"),
            "source": "manual",
            "created": datetime.utcnow().isoformat() + "Z"
        }
        signatures.append(sig)
        socketio.emit("signature_added", sig)
        return jsonify({"status": "added", "signature": sig})

    @app.route("/api/events")
    def get_events():
        """Get recent events with pagination"""
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
        alert_only = request.args.get("alert_only", "false").lower() == "true"
        
        events = stats["recent_events"]
        if alert_only:
            events = [e for e in events if e.get("alert")]
        
        return jsonify({
            "events": events[offset:offset+limit],
            "total": len(events),
            "offset": offset
        })

    @app.route("/api/export")
    def export_events():
        """Export events as JSON"""
        format_type = request.args.get("format", "json")
        alert_only = request.args.get("alert_only", "false").lower() == "true"
        
        events = stats["recent_events"]
        if alert_only:
            events = [e for e in events if e.get("alert")]
        
        if format_type == "json":
            return jsonify({
                "exported_at": datetime.utcnow().isoformat() + "Z",
                "total": len(events),
                "events": events
            })
        return jsonify({"error": "Unsupported format"}), 400

    @socketio.on("connect")
    def handle_connect():
        emit("connected", {"message": "Connected to QuantumDefender Cloud"})

    @socketio.on("disconnect")
    def handle_disconnect():
        pass

    return app, socketio, q


