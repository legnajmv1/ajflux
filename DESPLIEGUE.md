# Despliegue de AJFLUX en Rocky Linux con Docker

## 1. Instalar Docker en Rocky Linux

```bash
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"   # cierra sesión y vuelve a entrar para que aplique
```

## 2. Crear el archivo `.env`

```bash
cp .env.example .env
```

Completa:
- `DJANGO_SECRET_KEY`: genera uno con
  `python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"`
- `DJANGO_DEBUG=False`
- `DJANGO_ALLOWED_HOSTS`, `DJANGO_CSRF_TRUSTED_ORIGINS`: ver Bloque 6 (dominio).
- `SCAN_NETWORKS`: vacío para detección automática, o el/los CIDR del servidor
  (ej. `192.168.1.0/24`) si tiene varias interfaces y solo una debe escanearse.
- `TUNNEL_TOKEN`: el token del túnel de Cloudflare (Bloque 6).

Coloca también `firebase-credentials.json` (clave de servicio de Firebase) en
la raíz del proyecto — está en `.gitignore`/`.dockerignore`, no se versiona.

## 3. Levantar el sistema

```bash
docker compose up -d --build
```

Esto construye la imagen y arranca tres contenedores: `web` (gunicorn),
`monitor` (el ciclo de escaneo/ping en segundo plano) y `tunnel` (Cloudflare
Tunnel). `web` y `monitor` usan `network_mode: host` porque el escaneo ARP/nmap
necesita ver la LAN real del servidor, no una red Docker aislada.

## 4. Aplicar migraciones y crear el superusuario

```bash
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

## 5. Ver los logs

```bash
docker compose logs -f web       # panel y API
docker compose logs -f monitor   # escaneos, pings, alertas
docker compose logs -f tunnel    # estado del túnel de Cloudflare
```

## 6. Actualizar el sistema

```bash
git pull
docker compose up -d --build
docker compose exec web python manage.py migrate
```

## 7. Respaldar `data/ajflux.db`

La base SQLite vive en `./data/ajflux.db` en el host (montada por volumen,
sobrevive a `docker compose down`/reconstrucciones de la imagen).

```bash
cp data/ajflux.db data/ajflux-$(date +%Y%m%d-%H%M%S).db.bak
```

Para un respaldo en caliente sin copiar el archivo mientras SQLite escribe:

```bash
docker compose exec web python manage.py dbshell <<< ".backup /app/data/respaldo.db"
```
