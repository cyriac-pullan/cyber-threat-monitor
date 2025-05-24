FROM python:3.10-slim

WORKDIR /app
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run both services
CMD ["sh", "-c", "streamlit run dashboard.py --server.port=8501 & uvicorn run:app --host 0.0.0.0 --port 8000"] 