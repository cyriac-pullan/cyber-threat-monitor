from log_watcher import LogWatcher
from threat_detector import ThreatDetector
from response_engine import ResponseEngine
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
import os

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

def start_background_tasks():
    """Start background tasks in a separate thread"""
    def run_background():
        watcher = LogWatcher("sample_logs/auth.log")
        detector = ThreatDetector()
        responder = ResponseEngine()

        for line in watcher.watch():
            level, message = detector.detect(line)
            if level == "Alert":
                responder.send_alert(message)
            else:
                responder.send_normal(message)

    # Start background thread
    background_thread = threading.Thread(target=run_background, daemon=True)
    background_thread.start()

# Start background tasks when the application starts
@app.on_event("startup")
async def startup_event():
    start_background_tasks()

# For local development
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8501))
    uvicorn.run(app, host="0.0.0.0", port=port)
