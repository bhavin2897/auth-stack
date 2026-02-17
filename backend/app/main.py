import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
from jose import jwt
from .auth import verify_bearer

app = FastAPI(title="portal-backend")
bearer = HTTPBearer()

KEYCLOAK_BASE_URL = os.getenv("KEYCLOAK_BASE_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "trr-portal")
KEYCLOAK_AUDIENCE = os.getenv("KEYCLOAK_AUDIENCE", "portal-backend")

JWKS_URL = f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
ISSUER = f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}"

_jwks = None

async def get_jwks():
    global _jwks
    if _jwks is None:
        async with httpx.AsyncClient() as client:
            r = await client.get(JWKS_URL, timeout=10)
            r.raise_for_status()
            _jwks = r.json()
    return _jwks

async def require_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    token = creds.credentials
    jwks = await get_jwks()

    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        key = next((k for k in jwks["keys"] if k.get("kid") == kid), None)
        if not key:
            raise HTTPException(status_code=401, detail="Unknown key id (kid)")

        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=KEYCLOAK_AUDIENCE,
            issuer=ISSUER,
        )
        return claims
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/me")
async def me(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    claims = await verify_bearer(creds)
    return {
        "sub": claims.get("sub"),
        "preferred_username": claims.get("preferred_username"),
        "email": claims.get("email"),
        "aud": claims.get("aud"),
    }