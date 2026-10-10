# syntax=docker/dockerfile:1
# Dockerfile: Replicate "Rust Bindings - ubuntu-latest" CI job (x86_64)
#
# BuildKit secrets (never build args):
#   HCLI_API_KEY   - ida-hcli API key for downloading IDA Pro installer
#   GH_TOKEN       - optional GitHub PAT for a private SDK repo override
#
# Build args:
#   IDA_SDK_REPO   - SDK repo (default: HexRaysSA/ida-sdk)
#   IDA_SDK_REF    - SDK revision (default: CI's IDA 9.4 release patch)
#
# Usage:
#   docker build --platform linux/amd64 \
#     --secret id=HCLI_API_KEY,env=HCLI_API_KEY \
#     --secret id=GH_TOKEN,env=GH_TOKEN \
#     -t idax-rust-bindings \
#     -f docker/rust-bindings/Dockerfile .
#
#   docker run --platform linux/amd64 --rm idax-rust-bindings
#
# The build context must be the repository root.

# ==============================================================================
# Stage 1: Fetch the SDK with ephemeral credentials and remove Git metadata
# ==============================================================================
FROM --platform=linux/amd64 ubuntu:24.04 AS sdk-fetcher

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

ARG IDA_SDK_REPO=HexRaysSA/ida-sdk
ARG IDA_SDK_REF=6929db6868a524496eb66e76e4ec6c9d720a0594

COPY docker/rust-bindings/fetch-sdk.sh /usr/local/bin/fetch-sdk
RUN --mount=type=secret,id=GH_TOKEN \
    bash /usr/local/bin/fetch-sdk "${IDA_SDK_REPO}" "${IDA_SDK_REF}" /ida-sdk

# ==============================================================================
# Stage 2: Full build & test environment
# ==============================================================================
FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# -- System dependencies (mirrors the CI "Install dependencies (Linux)" step) --
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    clang \
    libclang-dev \
    # Additional deps needed for IDA installer + ida-hcli + Rust
    curl \
    git \
    ca-certificates \
    python3 \
    python3-pip \
    python3-venv \
    pkg-config \
    libssl-dev \
    file \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# -- Install uv (Python package manager, used for ida-hcli) --
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# -- Install Rust (stable, via rustup) --
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# -- Copy IDA SDK from stage 1 --
COPY --from=sdk-fetcher /ida-sdk /workspace/ida-sdk

# -- Resolve IDASDK path (mirrors CI "Resolve IDASDK and IDADIR paths" step) --
RUN mkdir -p /etc/environment.d && \
    SDK_ROOT="/workspace/ida-sdk" && \
    if [ -f "${SDK_ROOT}/ida-cmake/bootstrap.cmake" ]; then \
        echo "IDASDK=${SDK_ROOT}" > /etc/environment.d/ida.conf; \
    elif [ -f "${SDK_ROOT}/src/cmake/bootstrap.cmake" ] || [ -f "${SDK_ROOT}/src/cmake/idasdkConfig.cmake" ]; then \
        echo "IDASDK=${SDK_ROOT}/src" > /etc/environment.d/ida.conf; \
    elif [ -f "${SDK_ROOT}/src/ida-cmake/bootstrap.cmake" ]; then \
        echo "IDASDK=${SDK_ROOT}/src" > /etc/environment.d/ida.conf; \
    elif [ -f "${SDK_ROOT}/cmake/bootstrap.cmake" ] || [ -f "${SDK_ROOT}/cmake/idasdkConfig.cmake" ]; then \
        echo "IDASDK=${SDK_ROOT}" > /etc/environment.d/ida.conf; \
    else \
        echo "error: unable to locate SDK CMake package or bootstrap" && exit 1; \
    fi

# -- Install IDA Pro via ida-hcli; the key is available only in this RUN --
COPY scripts/select_hcli_license.py /usr/local/bin/select_hcli_license.py
RUN --mount=type=secret,id=HCLI_API_KEY,required=true \
    export HCLI_API_KEY="$(cat /run/secrets/HCLI_API_KEY)" && \
    # Determine license ID
    LICENSE_ID=$(uvx --from ida-hcli hcli --disable-updates license list | python3 /usr/local/bin/select_hcli_license.py) && \
    echo "Selected active named IDA product license" && \
    # Download the Linux x64 installer
    ASSET_KEY="release/9.4/ida-pro/ida-pro_94_x64linux.run" && \
    mkdir -p /tmp/ida-installer && \
    uvx --from ida-hcli hcli --disable-updates download --output-dir /tmp/ida-installer "$ASSET_KEY" && \
    # Find the downloaded installer
    INSTALLER_FILE=$(python3 -c "import glob; files=sorted(glob.glob('/tmp/ida-installer/*')); print(files[0] if files else '')") && \
    if [ -z "$INSTALLER_FILE" ]; then echo "error: no installer found"; ls -la /tmp/ida-installer; exit 1; fi && \
    echo "Using installer: $INSTALLER_FILE" && \
    # Install IDA
    (uvx --from ida-hcli hcli --disable-updates ida install --set-default --accept-eula --yes --license-id "$LICENSE_ID" "$INSTALLER_FILE" > /tmp/idax-install.log 2>&1 || \
        { sed -E 's/[0-9A-Fa-f]{2}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{2}/<license-id>/g' /tmp/idax-install.log; exit 1; }) && \
    # Cleanup installer
    rm -rf /tmp/ida-installer /tmp/idax-install.log

# -- Resolve IDADIR from ida-config.json (mirrors CI step) --
RUN IDADIR=$(python3 -c "\
import json, os; \
p = os.path.expanduser('~/.idapro/ida-config.json'); \
print(json.loads(open(p).read())['Paths']['ida-install-dir']) if os.path.exists(p) else print('')\
") && \
    echo "Resolved IDADIR=$IDADIR" && \
    echo "IDADIR=$IDADIR" >> /etc/environment && \
    echo "$IDADIR" > /tmp/idadir_path

# Set env vars that persist into the container
# (We read the resolved values and bake them in)
RUN IDADIR=$(cat /tmp/idadir_path) && \
    IDASDK=$(grep -oP 'IDASDK=\K.*' /etc/environment.d/ida.conf) && \
    echo "export IDADIR=\"${IDADIR}\"" >> /etc/bash.env && \
    echo "export IDASDK=\"${IDASDK}\"" >> /etc/bash.env && \
    echo "export LD_LIBRARY_PATH=\"${IDADIR}:\${LD_LIBRARY_PATH}\"" >> /etc/bash.env && \
    echo "export PATH=\"/root/.cargo/bin:/root/.local/bin:\${PATH}\"" >> /etc/bash.env && \
    rm -f /tmp/idadir_path

ENV BASH_ENV=/etc/bash.env

# Also set directly for non-bash invocations (docker run, RUN steps)
RUN . /etc/bash.env && \
    echo "ENV IDADIR=${IDADIR}" && \
    echo "ENV IDASDK=${IDASDK}" && \
    echo "ENV LD_LIBRARY_PATH=${IDADIR}" && \
    # Write a small script that the ENTRYPOINT can source
    printf '#!/bin/bash\nset -a\n. /etc/bash.env\nset +a\nexec "$@"\n' > /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/entrypoint.sh

# -- Copy the repository source --
COPY . /workspace/idax
WORKDIR /workspace/idax/bindings/rust

# Build/unit/examples and the dedicated initialized-runtime targets from Linux CI.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash", "/workspace/idax/docker/rust-bindings/run.sh"]
