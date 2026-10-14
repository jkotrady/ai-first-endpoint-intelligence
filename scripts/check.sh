#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
./scripts/go.sh vet ./cmd/... ./internal/... ./collectors/...
./scripts/go.sh test -race ./cmd/... ./internal/... ./collectors/...
./scripts/go.sh build -trimpath -buildvcs=false -o work/bin/forensics-console ./cmd/console
python3 -m unittest discover -s tests
python3 -m json.tool docs/api/openapi.json >/dev/null
python3 -m json.tool docs/api/pilot-openapi.json >/dev/null
if [ -x work/toolchains/node-v24.21.0-linux-x64/bin/node ]; then
 work/toolchains/node-v24.21.0-linux-x64/bin/node --check internal/console/web/app.js
 for js in internal/pilot/web/*.js; do
  work/toolchains/node-v24.21.0-linux-x64/bin/node --check "$js"
 done
fi
