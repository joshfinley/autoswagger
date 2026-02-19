FROM python:3.13-slim

WORKDIR /app

# Install dependencies first (layer caching)
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    python -m spacy download en_core_web_lg

# Copy source
COPY autoswagger/ autoswagger/

ENTRYPOINT ["python", "-m", "autoswagger"]
CMD ["-h"]
