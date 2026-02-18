# Buho Observabilidad (Dashboard local)

Proyecto Django local (SQLite) con UI moderna tipo SaaS y módulo de **Agentes** (fase dashboard/demo).

## Estructura principal

- `buho/` configuración principal Django.
- `ui/` vistas y templates del dashboard (Overview, Servers, Apps, Logs, Alerts, Settings).
- `agents/` nuevo módulo para agentes y tokens de enrollment.
- `accounts/` usuarios, organizaciones y comando `seed_demo`.
- `audit/` auditoría de acciones.
- `static/css/buho.css` design system base y dark mode.

## Arranque local

```bash
python manage.py migrate
python manage.py seed_demo
python manage.py runserver
```

### Credenciales demo

Password para todos: `BuhoDemo123!`

- `superadmin`
- `orgadmin`
- `analyst`
- `viewer`

## Módulo Agents

Rutas:

- `/agents/` lista y estado
- `/agents/<id>/` detalle por tabs
- `/agents/tokens/` gestión de tokens (SUPERADMIN y ORG_ADMIN)

Incluye:

- Modelo `Agent`
- Modelo `AgentEnrollmentToken`
- Auditoría de `CREATE_TOKEN` / `REVOKE_TOKEN` / `VIEW_AGENT` / `VIEW_TOKENS`
