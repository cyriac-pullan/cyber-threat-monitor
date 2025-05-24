FROM python:3.10-slim

WORKDIR /app
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p /app/sample_logs && \
    touch /app/sample_logs/auth.log && \
    touch /app/alerts.log

# Create startup script
RUN echo '#!/bin/sh\n\
python /app/log_generator.py &\n\
streamlit run /app/dashboard.py --server.port=8501 &\n\
uvicorn run:app --host 0.0.0.0 --port 8000\n\
' > /app/start.sh && chmod +x /app/start.sh

# Run all services
CMD ["/app/start.sh"] 