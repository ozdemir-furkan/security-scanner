import os
from pathlib import Path
from datetime import datetime
import zoneinfo

STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'scanner/static'),
]

# Timezone ayarları
TIME_ZONE = 'Europe/Istanbul'
USE_TZ = True
USE_L10N = True
USE_I18N = True
LANGUAGE_CODE = 'tr-tr'

# Varsayılan tarih formatı
DATETIME_FORMAT = 'd.m.Y H:i'
DATE_FORMAT = 'd.m.Y'
TIME_FORMAT = 'H:i' 