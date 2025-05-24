FROM python:3.10-slim

WORKDIR /app
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p /app/sample_logs && \
    touch /app/sample_logs/auth.log && \
    touch /app/alerts.log

# Run FastAPI on different port and proxy through Streamlit
CMD ["sh", "-c", "uvicorn run:app --host 0.0.0.0 --port 8001 & streamlit run dashboard.py --server.port=8000 --server.address=0.0.0.0"] 