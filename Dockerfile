FROM python:3.10-slim

WORKDIR /app
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Single service mode (Streamlit only)
CMD ["streamlit", "run", "dashboard.py", "--server.port=8000", "--server.address=0.0.0.0"] 