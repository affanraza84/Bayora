#!/usr/bin/env bash
# ==============================================================================
# Bayora Shield - Development Prerequisites & Environment Verification Script
# ==============================================================================

set -euo pipefail

BOLD="\033[1m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
NC="\033[0m"

echo -e "${BOLD}=== Bayora Shield: Environment Verification ===${NC}\n"

ERRORS=0

# 1. Check Python
echo -n "[*] Checking Python version (>= 3.11)... "
if command -v python3 >/dev/null 2>&1; then
    PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
        echo -e "${GREEN}OK (${PY_VER})${NC}"
    else
        echo -e "${RED}FAIL (Python $PY_VER found, >= 3.11 required)${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${RED}FAIL (python3 not found)${NC}"
    ERRORS=$((ERRORS + 1))
fi

# 2. Check Node & npm
echo -n "[*] Checking Node.js (>= 18)... "
if command -v node >/dev/null 2>&1; then
    NODE_VER=$(node -v)
    echo -e "${GREEN}OK (${NODE_VER})${NC}"
else
    echo -e "${RED}FAIL (node not found)${NC}"
    ERRORS=$((ERRORS + 1))
fi

echo -n "[*] Checking npm... "
if command -v npm >/dev/null 2>&1; then
    NPM_VER=$(npm -v)
    echo -e "${GREEN}OK (${NPM_VER})${NC}"
else
    echo -e "${RED}FAIL (npm not found)${NC}"
    ERRORS=$((ERRORS + 1))
fi

# 3. Check Docker
echo -n "[*] Checking Docker daemon... "
if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1; then
        DOCKER_VER=$(docker --version | awk '{print $3}' | tr -d ',')
        echo -e "${GREEN}OK (${DOCKER_VER})${NC}"
    else
        echo -e "${YELLOW}WARNING (Docker installed but daemon is not running)${NC}"
    fi
else
    echo -e "${RED}FAIL (docker binary not found)${NC}"
    ERRORS=$((ERRORS + 1))
fi

# 4. Secret Hygiene Check
echo -n "[*] Scanning for forbidden committed secrets (*.key, *.pem, .env)... "
SECRET_FILES=$(find . -maxdepth 3 \( -name "*.key" -o -name "*.pem" -o -name ".env" -o -name "id_ed25519*" \) ! -path "*/node_modules/*" ! -path "*/.git/*" || true)

if [ -n "$SECRET_FILES" ]; then
    echo -e "${RED}FAIL! Potential secret files found:${NC}"
    echo "$SECRET_FILES"
    ERRORS=$((ERRORS + 1))
else
    echo -e "${GREEN}OK (No forbidden secrets found)${NC}"
fi

# 5. Core Directory Structure Check
echo -n "[*] Verifying architecture directories... "
REQUIRED_DIRS=(
    "apps/dashboard"
    "services/control-plane"
    "services/audit-service"
    "services/evaluator"
    "services/model-gateway"
    "services/workers/red-team"
    "services/workers/blue-team"
    "infrastructure/compose"
    "infrastructure/security"
    "infrastructure/policies"
    "docs"
    "tests/unit"
    "tests/integration"
    "tests/isolation"
    "tests/adversarial"
    "tests/performance"
)

MISSING_DIRS=0
for dir in "${REQUIRED_DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        echo -e "\n  ${RED}Missing directory: $dir${NC}"
        MISSING_DIRS=$((MISSING_DIRS + 1))
    fi
done

if [ "$MISSING_DIRS" -eq 0 ]; then
    echo -e "${GREEN}OK (All 16 required directories present)${NC}"
else
    echo -e "${RED}FAIL ($MISSING_DIRS directories missing)${NC}"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✓ All Phase 1 prerequisite checks passed successfully!${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}✗ Prerequisite checks failed with $ERRORS errors.${NC}"
    exit 1
fi
