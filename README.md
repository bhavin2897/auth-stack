# auth-stack (Keycloak + PostgreSQL)

## Quick start
1. Copy env template:
   cp .env.example .env

2. Edit `.env` and set strong passwords.

3. Start:
   docker compose up -d

4. Logs:
   docker logs -f keycloak

Keycloak UI (temporary):
- http://SERVER_IP:8080
