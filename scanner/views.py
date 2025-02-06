import requests
import hashlib
import os
import datetime
import boto3
from dotenv import load_dotenv
from django.http import JsonResponse
import re
import json
from django.shortcuts import render
from .models import ScanResult
from django.utils import timezone
import zoneinfo

# .env dosyasını yükle
load_dotenv()

# 📌 *API Anahtarlarını Çek*
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY")
AWS_REGION = os.getenv("AWS_REGION")
SES_VERIFIED_EMAIL = os.getenv("SES_VERIFIED_EMAIL")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GOOGLE_CX_ID = os.getenv("GOOGLE_CX_ID")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY")

# 📌 *AWS SES istemcisi (E-posta Gönderimi İçin)*
ses_client = boto3.client(
    'ses',
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION
)

def format_results(result_type, data):
    """Sonuçları daha okunaklı formata çevirir"""
    if result_type == "whois":
        return f"""
🔍 WHOIS Sorgu Sonucu:
━━━━━━━━━━━━━━━━━━━━━━━━
📌 Domain: {data.get('domain')}
👤 Kayıt Eden: {data.get('registrar')}
📅 Oluşturulma Tarihi: {data.get('creation_date')}
🔄 Son Güncelleme: {data.get('updated_date')}
🌐 DNS Sunucuları: {', '.join(data.get('name_servers')) if isinstance(data.get('name_servers'), list) else data.get('name_servers')}
"""
    elif result_type == "ip":
        vt_data = data.get('VirusTotal', {})
        abuse_data = data.get('AbuseIPDB', {})
        return f"""
🔍 IP/Domain Tarama Sonucu:
━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Hedef: {vt_data.get('target', 'Bilinmiyor')}

VirusTotal Sonuçları:
📊 Zararlı Rapor Sayısı: {vt_data.get('malicious', 0)}
⚠️ Risk Durumu: {'Yüksek Risk!' if vt_data.get('malicious', 0) > 2 else 'Güvenli'}

AbuseIPDB Sonuçları:
📊 Güven Skoru: {abuse_data.get('abuse_score', 'Bilinmiyor')}
⚠️ Risk Durumu: {'Şüpheli!' if abuse_data.get('abuse_score', 0) > 35 else 'Güvenli'}
"""
    elif result_type == "password":
        password = data.get('password', '')
        # İlk iki karakter görünür, gerisi yıldız
        masked_password = password[:2] + '*' * (len(password) - 2) if len(password) > 2 else password + '**'
        return f"""
🔍 Şifre Sızıntı Kontrolü:
━━━━━━━━━━━━━━━━━━━━━━━━
🔑 Kontrol Edilen Şifre: {masked_password}
⚠️ Sızıntı Durumu: {'‼️ SİZDİRILMIŞ!' if data.get('breached') else '✅ Güvenli'}
📊 Sızıntı Sayısı: {data.get('breach_count', 0)}
"""
    elif result_type == "dork":
        results = data.get('GoogleDork', {}).get('results', [])
        result_text = "\n".join([f"🔗 {result}" for result in results]) if results else "Sonuç bulunamadı."
        return f"""
🔍 Google Dork Sonuçları:
━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Aranan: {data.get('GoogleDork', {}).get('query', 'Bilinmiyor')}

Bulunan Sonuçlar:
{result_text}
"""
    return str(data)

def home(request):
    result = None
    scan_type = request.GET.get('scan_type')
    
    try:
        if scan_type == "ip":
            ip = request.GET.get('searchInput')
            if ip:
                result = scan_ip(request, ip).content.decode('utf-8')
                result_dict = json.loads(result)
                formatted_result = format_results("ip", result_dict)
                
                # Veritabanına kaydet
                is_threat = result_dict.get('VirusTotal', {}).get('malicious', 0) > 2
                risk_score = result_dict.get('AbuseIPDB', {}).get('abuse_score', 0)
                
                # Türkiye saatini kullan
                istanbul_tz = zoneinfo.ZoneInfo('Europe/Istanbul')
                current_time = datetime.datetime.now(istanbul_tz)
                
                ScanResult.objects.create(
                    scan_type='ip',
                    query=ip,
                    result=formatted_result,
                    is_threat=is_threat,
                    risk_score=risk_score,
                    created_at=current_time
                )

        elif scan_type == "dork":
            query = request.GET.get('searchInput')
            if query:
                result = scan_google_dork(request, query).content.decode('utf-8')
                result_dict = json.loads(result)
                formatted_result = format_results("dork", result_dict)
                
                # Veritabanına kaydet
                has_results = bool(result_dict.get('GoogleDork', {}).get('results', []))
                ScanResult.objects.create(
                    scan_type='dork',
                    query=query,
                    result=formatted_result,
                    is_threat=has_results,
                    risk_score=50 if has_results else 0
                )

        elif scan_type == "password":
            password = request.GET.get('searchInput')
            if password:
                result = check_password_breach(request, password).content.decode('utf-8')
                result_dict = json.loads(result)
                formatted_result = format_results("password", result_dict)
                
                # Veritabanına kayıt için ilk iki karakteri göster
                masked_query = password[:2] + '*' * (len(password) - 2) if len(password) > 2 else password + '**'
                
                breach_count = result_dict.get('breach_count', 0)
                ScanResult.objects.create(
                    scan_type='password',
                    query=masked_query,  # İlk iki karakter görünür şekilde kaydet
                    result=formatted_result,
                    is_threat=breach_count > 0,
                    risk_score=min(breach_count, 100)
                )
                
        elif scan_type == "whois":
            domain = request.GET.get('searchInput')
            if domain:
                whois_result = whois_lookup(domain)
                formatted_result = format_results("whois", whois_result)
                
                # Veritabanına kaydet
                ScanResult.objects.create(
                    scan_type='whois',
                    query=domain,
                    result=formatted_result,
                    is_threat=False,
                    risk_score=0
                )

        if result is not None or scan_type == "whois":
            # Son 10 tarama sonucunu al
            recent_scans = ScanResult.objects.all()[:10]
            return render(request, "scanner/home.html", {
                "result": formatted_result,
                "recent_scans": recent_scans
            })

    except Exception as e:
        error_message = f"❌ Hata Oluştu: {str(e)}"
        ScanResult.objects.create(
            scan_type=scan_type or 'unknown',
            query=request.GET.get('searchInput', ''),
            result=error_message,
            is_threat=False,
            risk_score=0
        )
        return render(request, "scanner/home.html", {"result": error_message})

    return render(request, "scanner/home.html")

# 📌 *Hoşgeldiniz Mesajı*
def index(request):
    return JsonResponse({'message': 'Security Scanner API ye hoş geldiniz'})

# 📌 *E-Posta Gönderme Fonksiyonu*
def send_email(to_email, subject, message):
    try:
        ses_client.send_email(
            Source=f'"Güvenlik Ekibi" <{SES_VERIFIED_EMAIL}>',
            Destination={"ToAddresses": [to_email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": message}},
            },
        )
        print("✅ E-posta başarıyla gönderildi!")
    except Exception as e:
        print(f"❌ E-posta gönderme hatası: {e}")

# 📌 *VirusTotal API ile IP ve Domain Analizi*
def analyze_virustotal(target, is_ip=True):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}" if is_ip else f"https://www.virustotal.com/api/v3/domains/{target}"
    headers = {"x-apikey": VT_API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        malicious_count = data["data"]["attributes"].get("last_analysis_stats", {}).get("malicious", 0)

        if malicious_count > 2:
            send_email("furkanozd1231@gmail.com", "🚨 Güvenlik Uyarısı!!", f"{target} tehlikeli görünüyor! Verilerdeki Tehdit Sayısı {malicious_count}")

        return {"target": target, "malicious": malicious_count}

    return {"error": "VirusTotal API hatası!"}

# 📌 *AbuseIPDB API ile IP Analizi*
def analyze_abuseipdb(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json()
        abuse_score = data["data"].get("abuseConfidenceScore", 0)

        if abuse_score > 35:
            send_email("furkanozd1231@gmail.com", "🚨 Güvenlik Uyarısı!!", f"{ip_address} şüpheli olarak işaretlendi! risk skoru {abuse_score}")

        return {"ip": ip_address, "abuse_score": abuse_score}

    return {"error": "AbuseIPDB API hatası!"}

# 📌 *Google Dorking ile Sızıntı Araştırma*
def google_dork_search(query):
    url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "key": GOOGLE_API_KEY,
        "cx": GOOGLE_CX_ID,
        "q": f"site:pastebin.com OR site:github.com OR site:darkweb.report {query}"
    }

    response = requests.get(url, params=params)

    if response.status_code == 200:
        data = response.json()
        if "items" in data:
            results = [f"- {item['title']}: {item['link']}" for item in data["items"][:5]]
            message = "\n".join(results)
            send_email("furkanozd1231@gmail.com", f"🚨 {query} ile ilgili sızıntılar bulundu!", message)
            
            return {"query": query, "results": results}

    return {"query": query, "results": "Herhangi bir sızıntı bulunamadı."}

# 📌 *WHOIS Sorgusu*
def whois_lookup(domain):
    url = f"https://api.api-ninjas.com/v1/whois?domain={domain}"
    headers = {"X-Api-Key": WHOIS_API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        registrar = data.get('registrar', 'Bilinmiyor')
        creation_timestamp = data.get('creation_date', None)
        updated_timestamp = data.get('updated_date', None)
        name_servers = data.get('name_servers', 'Bilinmiyor')

        # Timestamp'i tarihe çevirme
        def convert_timestamp(ts):
            if isinstance(ts, list):  # Birden fazla tarih varsa
                return [datetime.datetime.utcfromtimestamp(int(t)).strftime('%Y-%m-%d %H:%M:%S') for t in ts]
            elif isinstance(ts, (int, float)):  # Tek tarih varsa
                return datetime.datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S')
            return "Bilinmiyor"

        creation_date = convert_timestamp(creation_timestamp)
        updated_date = convert_timestamp(updated_timestamp)

        message = f"""
🚨 WHOIS Bilgisi:
- Domain: {domain}
- Kayıt Eden: {registrar}
- Oluşturulma Tarihi: {creation_date}
- Son Güncelleme: {updated_date}
- DNS Sunucuları: {name_servers}
"""
        send_email("furkanozd1231@gmail.com", f"🚨 WHOIS Bilgisi: {domain}", message)

        return {
            "domain": domain,
            "registrar": registrar,
            "creation_date": creation_date,
            "updated_date": updated_date,
            "name_servers": name_servers
        }

    return {"error": "WHOIS API hatası!"}

# 📌 *Şifre Sızıntı Kontrolü (HIBP API)*
def check_password_breach(request, password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code == 200:
        breaches = response.text.splitlines()
        breach_count = 0

        for breach in breaches:
            hash_suffix, count = breach.split(":")
            if hash_suffix == suffix:
                breach_count = int(count)
                break

        # 📌 Eğer şifre sızdırıldıysa e-posta bildirimi gönder
        if breach_count > 0:
            subject = "🚨 Güvenlik Uyarısı: Şifreniz Sızdırıldı!"
            message = f"🚨 Şifreniz {breach_count} kez veri ihlallerinde tespit edilmiştir. Hemen değiştirin!"
            send_email("furkanozd1231@gmail.com", subject, message)

        return JsonResponse({
            "password": password,
            "breached": breach_count > 0,
            "breach_count": breach_count
        })

    return JsonResponse({"error": "HIBP API Hatası!"}, status=500)

# 📌 *API Endpointleri*
def scan_ip(request, ip):
    """
     Girilen veri bir IP adresi mi yoksa domain mi kontrol eder.
     - Eğer IP adresiyse → VirusTotal + AbuseIPDB kontrol eder.
     - Eğer Domain (URL) ise → Sadece VirusTotal kontrol eder.
     """

    # IP Adresi Kontrolü (Regex ile)
    ip_pattern = re.compile(
        r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    )  # 0-255 arasında 4 octet kontrolü

    if ip_pattern.match(ip):
        # Eğer girilen veri bir IP adresiyse
        result_vt = analyze_virustotal(ip, is_ip=True)
        result_abuse = analyze_abuseipdb(ip)  # AbuseIPDB sadece IP tarayabilir
        return JsonResponse({"VirusTotal": result_vt, "AbuseIPDB": result_abuse})

    else:
        # Eğer girilen veri bir Domain ise
        result_vt = analyze_virustotal(ip, is_ip=False)
        return JsonResponse({"VirusTotal": result_vt})  # AbuseIPDB burada çalışmaz

def scan_domain(request, domain):
    return JsonResponse({"VirusTotal": analyze_virustotal(domain, is_ip=False), "WHOIS": whois_lookup(domain)})

def scan_google_dork(request, query):
    return JsonResponse({"GoogleDork": google_dork_search(query)})

def scan_whois(request):
    domain = request.GET.get('domain')
    if domain:
        result = whois_lookup(domain)  # API ile WHOIS sorgusu yap
        return JsonResponse({"WHOIS": result})  # Sonucu JSON olarak döndür
    return JsonResponse({"error": "Lütfen bir domain girin!"})

def scan(request):
    return JsonResponse({'message': 'Tarama Başarılı!'})

def format_email_content(email_type, data):
    """E-posta içeriklerini formatlar"""
    if email_type == "virustotal":
        risk_message = '❌ YÜKSEK RİSK! Bu IP/Domain zararlı aktivitelerde kullanılmış.' if data['malicious'] > 2 else '✅ Güvenli görünüyor.'
        risk_level = 'Kritik' if data['malicious'] > 5 else 'Yüksek' if data['malicious'] > 2 else 'Düşük'
        recommendations = '- Bu IP/Domain ile olan tüm bağlantıları kesin\n- Sistemlerinizi kontrol edin\n- Güvenlik duvarı kurallarınızı güncelleyin' if data['malicious'] > 2 else '- Rutin güvenlik kontrollerinize devam edin'
        
        return f"""🚨 GÜVENLİK UYARISI: VirusTotal Tarama Sonucu
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Taranan Hedef: {data['target']}
📊 Tespit Edilen Tehdit Sayısı: {data['malicious']}
⚠️ Risk Değerlendirmesi:
{risk_message}
🔍 Detaylı Analiz:
• Toplam Tehdit Sayısı: {data['malicious']}
• Risk Seviyesi: {risk_level}
📌 Öneriler:
{recommendations}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ Security Scanner - Güvenlik Ekibi"""

    elif email_type == "abuseipdb":
        evaluation = '❌ ŞÜPHELİ AKTİVİTE TESPİT EDİLDİ!' if data['abuse_score'] > 35 else '✅ Güvenli görünüyor.'
        risk_level = 'Kritik' if data['abuse_score'] > 80 else 'Yüksek' if data['abuse_score'] > 35 else 'Düşük'
        recommendations = '- Bu IP ile olan bağlantıları izleyin\n- Güvenlik loglarınızı kontrol edin\n- Gerekirse IPyi engelleyin' if data['abuse_score'] > 35 else '- Normal izlemeye devam edin'
        
        return f"""🚨 GÜVENLİK UYARISI: AbuseIPDB Raporu
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Taranan IP: {data['ip']}
📊 Güven Skoru: {data['abuse_score']}/100
⚠️ Değerlendirme:
{evaluation}
🔍 Risk Analizi:
• Güven Skoru: {data['abuse_score']}/100
• Risk Seviyesi: {risk_level}
📌 Öneriler:
{recommendations}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ Security Scanner - Güvenlik Ekibi"""

    elif email_type == "password":
        risk_level = 'KRİTİK!' if data['breach_count'] > 1000 else 'YÜKSEK!' if data['breach_count'] > 100 else 'ORTA'
        
        return f"""🚨 GÜVENLİK UYARISI: Şifre Sızıntısı Tespit Edildi!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ ÖNEMLİ UYARI!
Kontrol edilen şifreniz {data['breach_count']} farklı veri sızıntısında tespit edildi!
🔍 Sızıntı Detayları:
• Tespit Sayısı: {data['breach_count']}
• Risk Seviyesi: {risk_level}
📌 Acil Eylem Önerileri:
1. Bu şifreyi kullanan tüm hesaplarınızı tespit edin
2. Şifrenizi hemen değiştirin
3. Her hesap için benzersiz şifreler kullanın
4. İki faktörlü doğrulama aktif edin
💡 Güvenli Şifre Önerileri:
• En az 12 karakter uzunluğunda olmalı
• Büyük/küçük harf, rakam ve özel karakterler içermeli
• Kişisel bilgiler içermemeli
• Her hesap için farklı olmalı
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ Security Scanner - Güvenlik Ekibi"""

    elif email_type == "dork":
        results_text = "\n".join(data['results']) if data['results'] else "Sonuç bulunamadı."
        evaluation = '❌ DİKKAT! Hassas bilgiler bulundu!' if data['results'] else '✅ Herhangi bir sızıntı tespit edilmedi.'
        recommendations = '- Bulunan içeriklerin kaldırılması için ilgili platformlarla iletişime geçin\n- Güvenlik önlemlerinizi gözden geçirin\n- Benzer sızıntıları önlemek için gerekli tedbirleri alın' if data['results'] else '- Düzenli olarak taramaya devam edin'
        
        return f"""🔍 Google Dork Araştırma Sonuçları
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Aranan Terim: {data['query']}
📝 Bulunan Sonuçlar:
{results_text}
⚠️ Değerlendirme:
{evaluation}
📌 Öneriler:
{recommendations}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ Security Scanner - Güvenlik Ekibi"""

    return None

def calculate_domain_age(creation_date):
    """Domain yaşını hesaplar"""
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    try:
        if isinstance(creation_date, str):
            created = datetime.datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
        else:
            return "Hesaplanamadı"
        
        age = datetime.datetime.now() - created
        years = age.days // 365
        months = (age.days % 365) // 30
        
        return f"{years} yıl {months} ay"
    except:
        return "Hesaplanamadı"

def get_domain_evaluation(creation_date):
    """Domain yaşına göre değerlendirme yapar"""
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    try:
        if isinstance(creation_date, str):
            created = datetime.datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S')
        else:
            return "Değerlendirme yapılamadı"
        
        age = (datetime.datetime.now() - created).days
        
        if age < 30:
            return "⚠️ DİKKAT: Yeni oluşturulmuş domain! Şüpheli olabilir."
        elif age < 180:
            return "⚠️ UYARI: Domain 6 aydan yeni. Dikkatli olunmalı."
        elif age < 365:
            return "ℹ️ BİLGİ: Domain 1 yıldan yeni ama makul bir süre geçmiş."
        else:
            return "✅ GÜVEN: Domain uzun süredir aktif. Daha güvenilir olabilir."
    except:
        return "Değerlendirme yapılamadı"