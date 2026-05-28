FROM python:3.13-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir .

FROM python:3.13-slim
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin/kube-chainsaw /usr/local/bin/kube-chainsaw
RUN useradd --create-home scanner
USER scanner
WORKDIR /scan
ENTRYPOINT ["kube-chainsaw"]
