# Intentionally vulnerable Dockerfile for supSec demo
FROM python
RUN apt-get update && apt-get install -y curl wget
RUN curl -sSL https://some-script.com/install.sh | bash
ENV API_KEY="sk-1234567890abcdef1234567890abcdef"
ADD . /app
EXPOSE 22
