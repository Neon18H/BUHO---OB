# Buho Observabilidad (Django + Frontend embebido con Vite/React)

Buho se mantiene como **un solo proyecto Django**. El frontend moderno "Acción Nocturna" vive dentro del mismo repo en `frontend/` y se integra en templates Django mediante `django-vite`.

## Stack UI embebido

- Django (auth, sesiones, CSRF, rutas y vistas)
- Vite + React + TypeScript + Tailwind (`frontend/`)
- Bundles build en `static/vite/` con `manifest.json`

## Rutas UI modernizadas

- `/auth/login/`
- `/auth/register/`
- `/`
- `/agents/overview/`
- `/agents/<id>/`
- `/servers/`, `/servers/<id>/`
- `/apps/`, `/apps/<id>/`
- `/logs/`, `/alerts/`, `/threats/`

Cada template renderiza un `div#app-root` con `data-page` y React monta desde allí.

## Logout + CSRF

- Logout forzado por **POST** en `/logout/`.
- `LOGOUT_REDIRECT_URL` y `LOGIN_URL` apuntan a `/auth/login/`.
- Frontend usa sesión Django (`credentials: "include"`) y manda `X-CSRFToken` desde cookie `csrftoken`.

## Comandos

```bash
# backend
python manage.py migrate
python manage.py runserver

# frontend
cd frontend
npm install
npm run dev
npm run build
```

En producción ejecuta `npm run build` y Django sirve los assets desde `static/vite/`.
