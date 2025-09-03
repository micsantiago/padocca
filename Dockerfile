# PADOCCA Docker Image
# Multi-stage build for optimized size

# Stage 1: Build environment
FROM kalilinux/kali-rolling AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    golang-go \
    rustc \
    cargo \
    python3 \
    python3-pip \
    build-essential \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
WORKDIR /build
COPY . /build/

# Compile Go components
RUN for tool in xss_sqli_scanner osint_intelligence intelligent_bruteforce; do \
        if [ -f "${tool}.go" ]; then \
            go build -ldflags="-s -w" -o "bin/${tool}" "${tool}.go"; \
        fi \
    done

# Compile tools-go components
RUN if [ -d "tools-go" ]; then \
        cd tools-go && \
        for tool in dns_enum web_crawler directory_fuzzer; do \
            if [ -f "${tool}.go" ]; then \
                go build -ldflags="-s -w" -o "../bin/${tool}" "${tool}.go"; \
            fi \
        done \
    fi

# Compile Rust components (if needed)
# RUN cd exploit_framework && cargo build --release

# Stage 2: Runtime environment
FROM kalilinux/kali-rolling

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    dnsutils \
    whois \
    curl \
    net-tools \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create padocca user
RUN useradd -m -s /bin/bash padocca

# Copy compiled binaries from builder
COPY --from=builder /build/bin /opt/padocca/bin
COPY --from=builder /build/*.py /opt/padocca/
COPY --from=builder /build/padocca.sh /opt/padocca/
COPY --from=builder /build/wordlists /opt/padocca/wordlists

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt 2>/dev/null || true

# Create main executable wrapper
RUN echo '#!/bin/bash\n\
if [ "$1" == "--help" ] || [ "$1" == "-h" ] || [ -z "$1" ]; then\n\
    python3 /opt/padocca/padocca.py "$@"\n\
else\n\
    case "$1" in\n\
        xss|xss-sqli)\n\
            shift\n\
            /opt/padocca/bin/xss_sqli_scanner "$@"\n\
            ;;\n\
        osint)\n\
            shift\n\
            /opt/padocca/bin/osint_intelligence "$@"\n\
            ;;\n\
        brute|bruteforce)\n\
            shift\n\
            /opt/padocca/bin/intelligent_bruteforce "$@"\n\
            ;;\n\
        scan)\n\
            shift\n\
            /opt/padocca/padocca.sh --scan "$@"\n\
            ;;\n\
        *)\n\
            python3 /opt/padocca/padocca.py "$@"\n\
            ;;\n\
    esac\n\
fi' > /usr/local/bin/padocca && \
    chmod +x /usr/local/bin/padocca

# Set permissions
RUN chmod -R 755 /opt/padocca && \
    chmod +x /opt/padocca/bin/* 2>/dev/null || true

# Switch to non-root user
USER padocca
WORKDIR /home/padocca

# Set environment
ENV PATH="/opt/padocca/bin:/usr/local/bin:${PATH}"
ENV PADOCCA_HOME="/opt/padocca"

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD padocca --version || exit 1

# Entry point
ENTRYPOINT ["padocca"]
CMD ["--help"]

# Labels
LABEL maintainer="Padocca Security Team"
LABEL version="2.0.0"
LABEL description="PADOCCA - Elite Pentesting Framework"
