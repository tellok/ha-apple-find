FROM python:3.13-slim
WORKDIR /workspace
COPY requirements.txt /tmp/findmy-requirements.txt
RUN pip install --no-cache-dir -r /tmp/findmy-requirements.txt requests unicorn rich
ENV PYTHONDONTWRITEBYTECODE=1
CMD ["python", "-m", "pytest", "-q"]
