FROM python:3.10-slim

WORKDIR /app

# Install nginx
RUN apt-get update && apt-get install -y nginx

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Copy application files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create a startup script
RUN echo '#!/bin/bash\n\
nginx\n\
streamlit run dashboard.py --server.port 8501 --server.address 0.0.0.0 &\n\
uvicorn run:app --host 0.0.0.0 --port 8000 &\n\
wait' > /app/start.sh && chmod +x /app/start.sh

# Expose the port
EXPOSE 8000

# Start the services
CMD ["/app/start.sh"] 