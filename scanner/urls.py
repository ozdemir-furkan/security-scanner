from django.urls import path
from . import views

urlpatterns = [

    path('',views.home,name='home'),
    path("scan/ip/<str:ip>/", views.scan_ip, name="scan_ip"),
    path("scan/domain/<str:domain>/", views.scan_domain, name="scan_domain"),
    path("scan/dork/<str:query>/", views.scan_google_dork, name="scan_dork"),
    path("scan/password/<str:password>/", views.check_password_breach, name="check_password_breach"),
    path('scan/whois/',views.scan_whois, name="scan_whois"),




]