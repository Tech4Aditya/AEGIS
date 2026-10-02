FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt
COPY backend/app /app/backend/app
COPY frontend /app/frontend
COPY policies /app/policies
COPY scenarios /app/scenarios
RUN mkdir -p /app/data
ENV PYTHONPATH=/app/backend
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
