#!/bin/bash -eu
# Runtime dependencies, pinned by version and hash.
pip3 install --require-hashes -r .clusterfuzzlite/requirements.txt

# Bundle every fuzz target with the package (and any data files it loads at import time).
for fuzzer in $(find "$SRC/ai-gateway-audit/fuzz" -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer" --paths "$SRC/ai-gateway-audit" \
    --add-data "ai_gateway_audit/controls.yaml:ai_gateway_audit"
done
