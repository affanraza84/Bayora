# Bayora Shield: Key Management & Secret Protection Specification

## 1. Cryptographic Key Taxonomy

Bayora Shield utilizes asymmetric and symmetric cryptography across two primary domains:

| Key Identifier | Algorithm | Purpose | Storage & Lifetime |
| :--- | :--- | :--- | :--- |
| **`AUDIT_ED25519_KEY`** | Ed25519 (256-bit) | Signs audit checkpoints and exported evidence bundles. | Mounted strictly into `audit-service` container volume (`audit_keys`). Never stored in DB. Rotated quarterly. |
| **`JWT_SIGNING_KEY`** | HMAC-SHA256 (256-bit) or RS256 | Signs and validates user authentication session tokens. | Injected via environment variable `JWT_SECRET_KEY` into `control-plane`. Rotated per deployment. |
| **`DB_CREDENTIALS`** | PostgreSQL Auth | Connects Control Plane and Audit Service to database. | Injected via `DATABASE_URL` / `POSTGRES_PASSWORD` env vars. Worker containers have no DB access. |
| **`LLM_PROVIDER_KEYS`** | API Tokens (OpenAI/Anthropic) | Upstream model inference authorization. | Mounted solely into `model-gateway` container. Workers never receive these keys. |

---

## 2. Local Key Generation Procedure

For local development and testing, Ed25519 keypairs can be generated using OpenSSL:

```bash
# Generate Ed25519 private key
openssl genpkey -algorithm Ed25519 -out infrastructure/security/audit_ed25519.key

# Extract public key
openssl pkey -in infrastructure/security/audit_ed25519.key -pubout -out infrastructure/security/audit_ed25519.pub

# Restrict permissions
chmod 600 infrastructure/security/audit_ed25519.key
chmod 644 infrastructure/security/audit_ed25519.pub
```

> **Warning:** Never commit `.key` files or private credentials to git. The `.gitignore` is configured to ignore `*.key`, `*.pem`, and `id_ed25519*`.
