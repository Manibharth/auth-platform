#!/usr/bin/env bash
# Rotate the JWT signing key without logging anyone out:
#  1. publish the current public key as a "previous" key (JWT_PREVIOUS_PUBLIC_KEYS)
#  2. add a new private-key version
#  3. redeploy; JWKS now serves both keys, old tokens verify until they expire (15 min)
#  4. after 15 minutes, drop the previous key on the next deploy
#   scripts/rotate_jwt_key.sh <project-id> <staging|production> <region>
set -euo pipefail
project="$1"; env="$2"; region="$3"; prefix="auth-platform-${env}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
gcloud secrets versions access latest --secret "${prefix}-jwt-private-key" --project "$project" > "$tmp/old.pem"
openssl pkey -in "$tmp/old.pem" -pubout > "$tmp/old.pub"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/new.pem" 2>/dev/null
gcloud secrets versions add "${prefix}-jwt-private-key" --project "$project" --data-file "$tmp/new.pem"
prev=$(python3 -c "import json,sys;print(json.dumps([open(sys.argv[1]).read()]))" "$tmp/old.pub")
gcloud run services update "${prefix}" --region "$region" --project "$project" \
  --update-env-vars "^@^JWT_PREVIOUS_PUBLIC_KEYS=${prev}"
echo "rotated; remove JWT_PREVIOUS_PUBLIC_KEYS after the access-token lifetime has passed"
