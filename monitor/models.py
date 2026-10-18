from django.db import models
from django.utils import timezone
import json


class Device(models.Model):
    """Dispositivo de red descubierto."""
    ip          = models.GenericIPAddressField(unique=True)
    mac         = models.CharField(max_length=17, blank=True, default='')
    hostname    = models.CharField(max_length=255, blank=True, default='')
    vendor      = models.CharField(max_length=100, blank=True, default='Unknown')
    device_type = models.CharField(max_length=50, default='desktop')
    first_seen  = models.DateTimeField(default=timezone.now)
    last_seen   = models.DateTimeField(default=timezone.now)
    is_gateway  = models.BooleanField(default=False)
    open_ports_json = models.TextField(default='[]')
    os_info     = models.CharField(max_length=200, blank=True, default='Desconocido')
    os_accuracy = models.IntegerField(default=0)
    services_json = models.TextField(default='{}')
    network     = models.CharField(max_length=50, blank=True, default='')

    STATUS_CHOICES = [
        ('online',  'Online'),
        ('offline', 'Offline'),
        ('warning', 'Warning'),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='online')

    latency_warning  = models.FloatField(null=True, blank=True)
    latency_critical = models.FloatField(null=True, blank=True)
    jitter_warning   = models.FloatField(null=True, blank=True)
    loss_warning     = models.FloatField(null=True, blank=True)
    qos_minimum      = models.FloatField(null=True, blank=True)
    threshold_notes  = models.TextField(blank=True, default='')

    active = models.BooleanField(default=True)  # False = desactivado por inactividad; conserva historial

    @property
    def open_ports(self):
        try:
            return json.loads(self.open_ports_json)
        except Exception:
            return []

    @open_ports.setter
    def open_ports(self, value):
        self.open_ports_json = json.dumps(value)

    @property
    def services(self):
        try:
            return json.loads(self.services_json)
        except Exception:
            return {}

    @services.setter
    def services(self, value):
        self.services_json = json.dumps(value)

    def get_latency_warning(self):
        from monitor.tasks import LATENCY_WARNING_MS
        return self.latency_warning if self.latency_warning is not None else LATENCY_WARNING_MS

    def get_latency_critical(self):
        from monitor.tasks import LATENCY_ALERT_MS
        return self.latency_critical if self.latency_critical is not None else LATENCY_ALERT_MS

    def get_loss_warning(self):
        from monitor.tasks import LOSS_ALERT_PCT
        return self.loss_warning if self.loss_warning is not None else LOSS_ALERT_PCT

    def get_jitter_warning(self):
        return self.jitter_warning if self.jitter_warning is not None else 30.0

    def get_qos_minimum(self):
        return self.qos_minimum if self.qos_minimum is not None else 0.0

    def __str__(self):
        return f"{self.ip} ({self.hostname or 'unknown'})"

    class Meta:
        ordering = ['ip']
        db_table = 'dispositivos'


class MetricSnapshot(models.Model):
    """Lectura de métricas QoS para un dispositivo en un momento dado."""
    device      = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='metrics')
    timestamp   = models.DateTimeField(default=timezone.now)
    latency     = models.FloatField(null=True, blank=True)
    jitter      = models.FloatField(null=True, blank=True)
    packet_loss = models.FloatField(default=0.0)
    qos_score   = models.FloatField(default=0.0)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['device', '-timestamp']),
        ]
        db_table = 'metricas'

    def __str__(self):
        return f"{self.device.ip} @ {self.timestamp} | lat={self.latency}ms"


class ScanReport(models.Model):
    """Reporte completo de un escaneo de red."""
    timestamp     = models.DateTimeField(default=timezone.now)
    network       = models.CharField(max_length=50)
    total_found   = models.IntegerField(default=0)
    online_count  = models.IntegerField(default=0)
    avg_latency   = models.FloatField(null=True, blank=True)
    avg_qos       = models.FloatField(null=True, blank=True)
    scan_duration = models.FloatField(default=0.0)
    devices_json  = models.TextField(default='[]')

    @property
    def devices_snapshot(self):
        try:
            return json.loads(self.devices_json)
        except Exception:
            return []

    class Meta:
        ordering = ['-timestamp']
        db_table = 'reportes_escaneo'

    def __str__(self):
        return f"Scan {self.timestamp} — {self.total_found} devices"


class Alert(models.Model):
    """Alerta de red."""
    LEVEL_CHOICES = [
        ('info',     'Info'),
        ('warning',  'Warning'),
        ('critical', 'Critical'),
    ]
    TYPE_CHOICES = [
        ('latency',     'Latencia'),
        ('jitter',      'Jitter'),
        ('loss',        'Pérdida de paquetes'),
        ('qos',         'QoS bajo'),
        ('disconnect',  'Desconexión'),
        ('new_device',  'Nuevo dispositivo'),
        ('other',       'Otro'),
    ]
    device     = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='alerts', null=True, blank=True)
    level      = models.CharField(max_length=10, choices=LEVEL_CHOICES, default='info')
    alert_type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='other')
    message    = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    resolved  = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
        db_table = 'alertas'

    def __str__(self):
        return f"[{self.level.upper()}] {self.message}"


class UserProfile(models.Model):
    """Perfil de usuario — define el rol dentro de AJFLUX."""
    ROLE_CHOICES = [
        ('admin',    'Administrador'),
        ('operator', 'Operador'),
        ('viewer',   'Visualizador'),
    ]
    user       = models.OneToOneField('auth.User', on_delete=models.CASCADE, related_name='profile')
    role       = models.CharField(max_length=10, choices=ROLE_CHOICES, default='viewer')
    fcm_token  = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(default=timezone.now)

    def is_admin(self):
        return self.role == 'admin'

    def is_operator(self):
        return self.role == 'operator'

    def is_viewer(self):
        return self.role == 'viewer'

    # Permisos derivados del rol — no se almacenan en la BD
    def can_scan(self):
        return self.role in ('admin', 'operator')

    def can_export(self):
        return True  # todos pueden exportar

    def can_config(self):
        return self.role in ('admin', 'operator')

    def can_manage_users(self):
        return self.role == 'admin'

    def __str__(self):
        return f"{self.user.username} ({self.get_role_display()})"

    class Meta:
        db_table = 'perfiles_usuario'