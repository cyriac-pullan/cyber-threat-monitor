from log_watcher import LogWatcher
from threat_detector import ThreatDetector
from response_engine import ResponseEngine
import subprocess
import threading
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import json
from ml_detector import MLDetector
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn

# Initialize components
threat_detector = ThreatDetector()
response_engine = ResponseEngine()
ml_detector = MLDetector()

# Create FastAPI app
app = FastAPI()

# Add CORS middleware with more permissive configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
    expose_headers=["*"],
    max_age=3600,  # Cache preflight requests for 1 hour
)

# Add trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"]  # Allow all hosts
)

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok"}

# API endpoints
@app.get("/api/risk-assessment")
async def get_risk_assessment():
    try:
        data = threat_detector.get_risk_assessment()
        return JSONResponse(
            content=data,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts")
async def get_alerts():
    try:
        data = response_engine.get_alerts()
        return JSONResponse(
            content=data,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/status")
async def get_status():
    try:
        data = response_engine.get_system_status()
        return JSONResponse(
            content=data,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.options("/{full_path:path}")
async def options_route(full_path: str):
    return JSONResponse(
        content={},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "*",
            "Access-Control-Max-Age": "3600",
        }
    )

def run_dashboard():
    subprocess.run(["streamlit", "run", "dashboard.py"])

def run_api_server():
    uvicorn.run(app, host="0.0.0.0", port=8000)

def main():
    print("Starting Cyber Threat Monitor...")

    # Start the Streamlit dashboard in a daemon thread
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()

    # Start the FastAPI server in a daemon thread
    api_thread = threading.Thread(target=run_api_server, daemon=True)
    api_thread.start()

    # Start the log watcher
    watcher = LogWatcher("sample_logs/auth.log")
    detector = ThreatDetector()
    responder = ResponseEngine()

    for line in watcher.watch():
        level, message = detector.detect(line)
        if level == "Alert":
            responder.send_alert(message)
        else:
            responder.send_normal(message)

if __name__ == "__main__":
    main()
