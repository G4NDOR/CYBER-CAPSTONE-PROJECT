import os
import glob
import importlib.util
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

app = FastAPI(title="PORTSOC Alert Enrichment Engine")

# In-memory storage for demonstration alerts
alerts_db = [
    {
        "id": "ALT-1001",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "rule_name": "Multiple Failed Authentication Attempts",
        "severity": "HIGH",
        "source_ip": "198.51.100.42",
        "enriched_verdicts": [
            {"module": "AbuseIPDB", "score": 95, "verdict": "Malicious"},
            {"module": "AlienVault OTX", "pulses": 4, "verdict": "Threat Actor Linked"}
        ]
    }
]

def execute_team_plugins(alert: dict):
    """Dynamically executes all Python modules dropped in the plugins directory."""
    plugin_files = glob.glob("/opt/alert-enrichment/plugins/*.py")
    results = []
    
    for filepath in plugin_files:
        module_name = os.path.basename(filepath)[:-3]
        if module_name.startswith("__") or module_name == "base_plugin":
            continue
        try:
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "plugin_instance"):
                res = mod.plugin_instance.run(alert)
                results.append(res)
        except Exception as e:
            results.append({"module": module_name, "error": str(e)})
            
    return results

@app.post("/api/v1/alerts")
async def ingest_alert(request: Request):
    alert = await request.json()
    if "id" not in alert:
        alert["id"] = f"ALT-{len(alerts_db) + 1001}"
    if "timestamp" not in alert:
        alert["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
    enrichment = execute_team_plugins(alert)
    alert["enriched_verdicts"] = enrichment
    alerts_db.insert(0, alert)
    return {"status": "success", "alert_id": alert["id"], "enrichment": enrichment}

@app.get("/api/v1/alerts")
async def get_alerts():
    return alerts_db

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    rows = ""
    for a in alerts_db:
        tags = "".join([
            f"<span class='tag'>{e.get('module')}: {e.get('verdict', e.get('score', e.get('error', 'N/A')))}</span> "
            for e in a.get("enriched_verdicts", [])
        ]) or "<span style='color: #6e7681;'>No enrichment plugins triggered</span>"

        severity = a.get("severity", "LOW").upper()
        badge_class = severity.lower()

        rows += f"""
        <tr>
            <td style="font-family: monospace; color: #58a6ff;">{a.get('id')}</td>
            <td style="color: #8b949e; font-size: 12px;">{a.get('timestamp')}</td>
            <td><strong>{a.get('rule_name', 'Unknown Rule')}</strong></td>
            <td><span class="badge {badge_class}">{severity}</span></td>
            <td><code>{a.get('source_ip', 'N/A')}</code></td>
            <td>{tags}</td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PORTSOC Alert Triage Engine</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 32px; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #30363d; padding-bottom: 16px; margin-bottom: 24px; }}
            h1 {{ color: #f0f6fc; margin: 0; font-size: 22px; }}
            .subtitle {{ color: #8b949e; font-size: 14px; margin-top: 4px; }}
            .node-status {{ font-size: 12px; background: #23863633; color: #3fb950; border: 1px solid #238636; padding: 4px 10px; border-radius: 20px; font-weight: 500; }}
            table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; border: 1px solid #30363d; }}
            th, td {{ padding: 14px 16px; text-align: left; border-bottom: 1px solid #21262d; font-size: 13px; }}
            th {{ background: #21262d; color: #8b949e; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}
            tr:hover {{ background: #1c2128; }}
            .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
            .badge.high {{ background: #da363333; color: #f85149; border: 1px solid #da3633; }}
            .badge.medium {{ background: #d2992233; color: #e3b341; border: 1px solid #d29922; }}
            .badge.low {{ background: #1f6feb33; color: #58a6ff; border: 1px solid #1f6feb; }}
            .tag {{ background: #388bfd1a; color: #58a6ff; border: 1px solid #388bfd40; padding: 3px 8px; border-radius: 4px; font-size: 12px; display: inline-block; margin: 2px 0; }}
            code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; color: #7ee787; font-size: 12px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>PORTSOC Alert Enrichment & Triage Dashboard</h1>
                <div class="subtitle">Real-time alert correlation & threat scoring engine</div>
            </div>
            <div class="node-status">● Cluster Active (k3s)</div>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Alert ID</th>
                    <th>Timestamp</th>
                    <th>Detection Rule</th>
                    <th>Severity</th>
                    <th>Source Indicator</th>
                    <th>Automated Enrichment Details</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </body>
    </html>
    """
