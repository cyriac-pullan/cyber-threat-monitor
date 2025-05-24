FROM python:3.10-slim

WORKDIR /app
COPY . .

# Install system dependencies for Nginx
RUN apt-get update && apt-get install -y nginx && rm -rf /var/lib/apt/lists/*

# Configure Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create startup script
RUN echo '#!/bin/bash\n\
service nginx start\n\
streamlit run dashboard.py --server.port=8501 --server.address=0.0.0.0 &\n\
uvicorn run:app --host=0.0.0.0 --port=8000\n\
' > /app/start.sh && chmod +x /app/start.sh

CMD ["./start.sh"] 