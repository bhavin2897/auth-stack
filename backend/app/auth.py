import os
import time
import httpx
from jose import jwt
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

KEYCLOAK_ISSUER = os.environ["KEYCLOAK_ISSUER"]
KEYCLOAK_JWKS_URL = os.environ["KEYCLOAK_JWKS_URL"]
KEYCLOAK_AUDIENCE = os.environ["KEYCLOAK_AUDIENCE"]

_JWKS = None
_JWKS_TS = 0
_JWKS_TTL = 3600  # 1 hour

async def _get_jwks():
    global _JWKS, _JWKS_TS
    now = time.time()
    if _JWKS is None or (now - _JWKS_TS) > _JWKS_TTL:
        async with httpx.AsyncClient() as client:
            r = await client.get(KEYCLOAK_JWKS_URL, timeout=10)
            r.raise_for_status()
            _JWKS = r.json()
            _JWKS_TS = now
    return _JWKS

async def verify_bearer(creds: HTTPAuthorizationCredentials):
    token = creds.credentials
    jwks = await _get_jwks()

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        key = next((k for k in jwks["keys"] if k.get("kid") == kid), None)
        if not key:
            raise HTTPException(status_code=401, detail="Unknown token key (kid)")

        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=KEYCLOAK_ISSUER,
            audience=KEYCLOAK_AUDIENCE,
        )
        return claims
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
