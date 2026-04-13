FROM python:3.12-slim AS builder

ENV UV_VERSION=0.11.6
RUN pip install --no-cache-dir "uv==${UV_VERSION}"

WORKDIR /app
COPY pyproject.toml ./
COPY src/ ./src/
RUN uv sync --no-dev --frozen 2>/dev/null || uv pip install --system .

FROM python:3.12-slim

RUN groupadd --system --gid 10001 supsec && \
    useradd --system --uid 10001 --gid supsec --home /app supsec

WORKDIR /scan

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/supsec /usr/local/bin/supsec 2>/dev/null || true
COPY --from=builder /app/src /app/src

ENV PYTHONPATH=/app/src

USER supsec

HEALTHCHECK --interval=60s --timeout=3s --retries=1 \
    CMD ["python", "-c", "import supsec; print('ok')"]

ENTRYPOINT ["python", "-m", "supsec.cli"]
CMD ["scan", "."]
