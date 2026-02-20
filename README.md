# Buho Observabilidad (Dashboard local)

Proyecto Django local (SQLite) con UI moderna tipo SaaS y módulo de **Agentes** (fase dashboard/demo).

## Estructura principal

- `buho/` configuración principal Django.
- `ui/` vistas y templates del dashboard (Overview, Servers, Apps, Logs, Alerts, Settings).
- `agents/` nuevo módulo para agentes y tokens de enrollment.
- `accounts/` usuarios, organizaciones y registro inicial (`/register`).
- `audit/` auditoría de acciones.
- `static/css/buho.css` design system base y dark mode.

## Arranque local

```bash
python manage.py migrate
python manage.py runserver

# Inicializa la primera organización en http://127.0.0.1:8000/register/
# (Opcional desarrollo) python manage.py seed_users
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

## Notas de despliegue del instalador de agentes

- Los scripts servidos por Buho (`/agents/download/agent.py` y `/agents/download/windows.ps1`) se generan desde backend en cada request.
- Después de cambiar la lógica de generación en Django, reinicia el servidor (`python manage.py runserver`) para asegurarte de servir la versión actualizada del instalador.

## Agente PRO (Windows + Linux)

El agente descargable (`/agents/download/agent.py`) ahora incorpora:

- loop continuo con manejo global de errores + reintentos exponenciales en heartbeat/ingest;
- cola local `spool.jsonl` (límite 50MB/5000 eventos) para no perder telemetría si el backend está temporalmente caído;
- métricas infra reales (CPU, RAM, swap, disco por partición, IO disco, red, uptime/load);
- procesos/puertos listening, servicios (systemd o Windows Services) y descubrimiento heurístico de apps;
- ingest incremental de logs de archivos configurados con redacción de secretos;
- parse de access logs HTTP (Nginx/Apache/IIS si se apunta la ruta de log) para `http.requests.count`, `http.errors.count`, `http.latency.ms`.

### Configuración recomendada en `config.json`

```json
{
  "logs_sources": [{"type": "file", "path": "/var/log/syslog", "name": "syslog"}],
  "http_logs": ["/var/log/nginx/access.log", "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log"]
}
```

### Permisos y fallbacks

- **Windows Task Scheduler**: el instalador intenta crear tarea como `SYSTEM` con restart-on-failure; si no hay privilegios suficientes, cae a tarea en contexto de usuario.
- **Linux systemd**: el instalador intenta user service (`~/.config/systemd/user/buho-agent.service`) con `Restart=always`; si `systemctl` no existe, usa `nohup`.
- Lectura de algunos logs del sistema (EventLog, journald, syslog) puede requerir permisos elevados; el agente omite fuentes inaccesibles y continúa.

### Troubleshooting rápido de estado OFFLINE

1. Verifica `buho-agent.log` en el host del agente.
2. Ejecuta `python agent.py --run --config config.json --once` para validar conectividad y credenciales.
3. Revisa que el reloj del host sea correcto (desfases grandes afectan ventanas de heartbeat).
4. En Buho, ejecutar `python manage.py evaluate_alerts` para recalcular alertas de heartbeat faltante.


## Despliegue en Railway (CSRF/HTTPS)

Configura estas variables de entorno en Railway para evitar `403 CSRF verification failed` en login/registro y otros POST del dashboard:

- `DEBUG=0`
- `ALLOWED_HOSTS=<domain>.up.railway.app`
- `CSRF_TRUSTED_ORIGINS=https://<domain>.up.railway.app`

Si tienes más de un dominio, usa valores separados por coma en `ALLOWED_HOSTS` y `CSRF_TRUSTED_ORIGINS`.

## Provider/Discovery testing (local)

- Simular **Railway**: ejecutar agente con variables `RAILWAY_ENVIRONMENT=production RAILWAY_PROJECT_ID=demo`.
- Simular **AWS**: exportar `AWS_REGION=us-east-1 AWS_EXECUTION_ENV=local-test`.
- Simular **Azure**: exportar `WEBSITE_INSTANCE_ID=demo-azure`.
- Simular **GCP**: exportar `GOOGLE_CLOUD_PROJECT=demo-project`.
- Forzar tags/env en config del agente (`tags`, `environment`) y validar en UI de Overview/Agents/Apps.
- Endpoint de discovery: `POST /api/ingest/discovery` (usa cabeceras `X-Buho-Agent-Id` y `X-Buho-Agent-Key`).
