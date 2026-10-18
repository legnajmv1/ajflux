FROM python:3.11-slim

# Herramientas de red que usa monitor/scanner.py (nmap para puertos/SO/fabricante,
# ping/traceroute/ip para latencia y descubrimiento, net-tools para compatibilidad)
# + gcc, porque psutil no trae wheel precompilado para esta imagen/arquitectura
# y compila su extensión C en el install.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        iputils-ping \
        iproute2 \
        net-tools \
        traceroute \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn \
    && apt-get purge -y build-essential && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /root/.cache

COPY . .

# collectstatic solo necesita que SECRET_KEY exista (no un valor real): el
# .env de verdad llega en runtime vía env_file en docker-compose.yml.
RUN DJANGO_SECRET_KEY=solo-para-collectstatic-no-se-usa-en-runtime \
    python manage.py collectstatic --noinput

EXPOSE 8000

CMD ["gunicorn", "ajflux.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2"]
