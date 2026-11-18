#!/usr/bin/env bash
# Add the JWT signing key and MFA encryption key to Secret Manager WITHOUT passing
# them through Terraform state. Run once per environment after `terraform apply`.
#   scripts/bootstrap_secrets.sh <project-id> <staging|production>
set -euo pipefail
project="$1"; env="$2"; prefix="auth-platform-${env}"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$tmp/jwt.pem" 2>/dev/null
gcloud secrets versions add "${prefix}-jwt-private-key" --project "$project" --data-file "$tmp/jwt.pem"

python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode(),end='')" > "$tmp/mfa.key"
gcloud secrets versions add "${prefix}-mfa-encryption-key" --project "$project" --data-file "$tmp/mfa.key"
echo "secrets added for ${env}"
