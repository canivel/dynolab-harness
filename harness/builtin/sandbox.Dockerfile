FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates git procps && rm -rf /var/lib/apt/lists/*
RUN useradd -m -s /bin/bash agent && mkdir /workspace && chown agent /workspace
# Running the T1 tests must not drop __pycache__ into the protected tests/ dir.
ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /workspace
CMD ["sleep", "infinity"]
