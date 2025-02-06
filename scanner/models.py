from django.db import models
from django.utils import timezone
from datetime import datetime
import zoneinfo  # Python 3.9+ için önerilen timezone modülü

class ScanResult(models.Model):
    SCAN_TYPES = [
        ('ip', 'IP/Domain Tarama'),
        ('dork', 'Google Dorking'),
        ('password', 'Şifre Sızıntı'),
        ('whois', 'WHOIS Sorgusu'),
    ]

    scan_type = models.CharField(max_length=10, choices=SCAN_TYPES)
    query = models.CharField(max_length=255)  # Aranan değer
    result = models.TextField()  # Sonuç
    created_at = models.DateTimeField(auto_now_add=True)
    is_threat = models.BooleanField(default=False)  # Tehdit durumu
    risk_score = models.IntegerField(default=0)  # Risk skoru (0-100)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.get_scan_type_display()} - {self.query}"

    def save(self, *args, **kwargs):
        if not self.id:  # Yeni kayıt oluşturuluyorsa
            istanbul_tz = zoneinfo.ZoneInfo('Europe/Istanbul')
            self.created_at = datetime.now(istanbul_tz)
        super(ScanResult, self).save(*args, **kwargs)
