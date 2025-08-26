"""
DJANGO WEB SİTELERİ İÇİN EKSİKSİZ KORUMA, MİDDLEWARE OLARAK HAZIRLANDI
"""


import os
import re
import json
import time
import socket
import logging
import hashlib
import smtplib
import ipaddress
import requests
import urllib.parse
from collections import defaultdict, deque
from threading import Thread
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from django.conf import settings
from django.http import (
    HttpResponseBadRequest,
    HttpResponseForbidden,
    HttpResponseRedirect,
    JsonResponse
)
from django.core.cache import cache
from django.contrib.auth import get_user_model, login, logout
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin

# Rate Limit koruması için middleware
class RateLimitMiddleware:
    async_mode = False
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Rate limit ayarları
        self.max_requests = 30  # 1 dakikada maksimum istek sayısı
        self.time_window = 60   # Zaman penceresi (saniye)
        self.cooldown_time = 120  # Cooldown süresi (saniye)

    def __call__(self, request):
        # IP adresini al
        ip_address = self.get_client_ip(request)
        
        # Rate limit kontrolü
        if self.is_rate_limited(ip_address):
            return render(request, '429.html', status=429)
        
        # İsteği kaydet
        self.record_request(ip_address)
        
        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """Kullanıcının gerçek IP adresini al"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def is_rate_limited(self, ip_address):
        """IP adresinin rate limit'e takılıp takılmadığını kontrol et"""
        # Cooldown kontrol anahtarı
        cooldown_key = f"rate_limit_cooldown:{ip_address}"
        
        # Eğer cooldown süresindeyse, rate limit aktif
        if cache.get(cooldown_key):
            return True
        
        # İstek sayısı kontrol anahtarı
        request_key = f"rate_limit_requests:{ip_address}"
        request_data = cache.get(request_key, {'count': 0, 'first_request': time.time()})
        
        current_time = time.time()
        first_request_time = request_data['first_request']
        
        # Zaman penceresi geçtiyse sıfırla
        if current_time - first_request_time > self.time_window:
            return False
        
        # Maksimum istek sayısını aştıysa rate limit aktif et
        if request_data['count'] >= self.max_requests:
            # Cooldown başlat
            cache.set(cooldown_key, True, self.cooldown_time)
            # İstek verilerini temizle
            cache.delete(request_key)
            return True
        
        return False

    def record_request(self, ip_address):
        """İsteği kaydet"""
        request_key = f"rate_limit_requests:{ip_address}"
        request_data = cache.get(request_key, {'count': 0, 'first_request': time.time()})
        
        current_time = time.time()
        
        # Zaman penceresi geçtiyse sıfırla
        if current_time - request_data['first_request'] > self.time_window:
            request_data = {'count': 1, 'first_request': current_time}
        else:
            request_data['count'] += 1
        
        # Cache'e kaydet (time_window + cooldown_time kadar sakla)
        cache.set(request_key, request_data, self.time_window + self.cooldown_time)


# Logging setup
security_logger = logging.getLogger('security')


logger = logging.getLogger(__name__)

class ComprehensiveSecurityMiddleware(MiddlewareMixin):
    """
    ÜST DÜZEY GÜVENLİK MİDDLEWARE - HIPER GÜÇLÜ KORUMA SİSTEMİ
    Tüm injection türlerine, advanced persistent threats ve zero-day saldırılara karşı koruma
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        
        # Rate limiting ve IP tracking
        self.request_counts = defaultdict(deque)
        self.blocked_ips = set()
        self.suspicious_ips = defaultdict(int)
        self.honeypot_triggers = set()
        
        # Advanced SQL Injection Patterns (Çok detaylı)
        self.sql_patterns = [
            # Temel SQL komutları
            r"(\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC(?:UTE)?|UNION|SCRIPT|TRUNCATE|MERGE)\b)",
            r"(\b(?:GRANT|REVOKE|COMMIT|ROLLBACK|SAVEPOINT|SET|USE|SHOW|DESCRIBE|EXPLAIN)\b)",
            
            # Gelişmiş mantıksal bypass teknikleri
            r"(\b(?:OR|AND)\s+(?:\d+\s*[=<>!]+\s*\d+|['\"][\w\s]*['\"]\s*[=<>!]+\s*['\"][\w\s]*['\"]))",
            r"(\b(?:OR|AND)\s+(?:TRUE|FALSE|\d+)\s*(?:--|\#|\/\*))",
            r"(\b(?:OR|AND)\s+[\'\"][\w\s]*[\'\"][\s]*LIKE[\s]*[\'\"][\w\s%]*[\'\"])",
            r"(\b(?:OR|AND)\s+[\'\"][\w\s]*[\'\"][\s]*REGEXP[\s]*[\'\"].*?[\'\"])",
            
            # Time-based blind SQL injection
            r"(\bWAITFOR\s+DELAY\s+['\"][\d:]+['\"])",
            r"(\bSLEEP\s*\(\s*\d+\s*\))",
            r"(\bBENCHMARK\s*\(\s*\d+\s*,)",
            r"(\bPG_SLEEP\s*\(\s*\d+\s*\))",
            
            # Boolean-based blind SQL injection
            r"(\bCASE\s+WHEN\s+.+\s+THEN\s+.+\s+ELSE\s+.+\s+END)",
            r"(\bIF\s*\(\s*.+\s*,\s*.+\s*,\s*.+\s*\))",
            r"(\bIIF\s*\(\s*.+\s*,\s*.+\s*,\s*.+\s*\))",
            
            # Union-based injection
            r"(\bUNION\s+(?:ALL\s+)?SELECT\b)",
            r"(\bUNION\s+(?:DISTINCT\s+)?SELECT\b)",
            r"(\)\s+UNION\s+(?:ALL\s+)?SELECT\s+)",
            
            # Error-based injection
            r"(\bEXTRACTVALUE\s*\(\s*.+\s*,\s*.+\s*\))",
            r"(\bUPDATEXML\s*\(\s*.+\s*,\s*.+\s*,\s*.+\s*\))",
            r"(\bEXP\s*\(\s*~\s*\(\s*SELECT\b)",
            
            # Stacked queries
            r"(;\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b)",
            r"(;\s*EXEC\s*\(\s*['\"])",
            r"(;\s*DECLARE\s+@\w+)",
            
            # Advanced function abuse
            r"(\b(?:CONVERT|CAST|CHAR|ASCII|SUBSTRING|MID|LEFT|RIGHT|CONCAT|LOAD_FILE|INTO\s+OUTFILE)\b)",
            r"(\bCHAR\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\))",
            r"(\bCONCAT\s*\(\s*.+\s*,\s*.+\s*\))",
            
            # Database-specific functions
            r"(\b(?:xp_cmdshell|sp_executesql|sp_configure|sp_addextendedproc)\b)",
            r"(\b(?:pg_read_file|pg_ls_dir|pg_stat_file)\b)",
            r"(\b(?:sys_exec|sys_eval|load_extension)\b)",
            
            # Information gathering
            r"(\b(?:INFORMATION_SCHEMA|sysobjects|syscolumns|sysusers|sysdatabases)\b)",
            r"(\b(?:mysql\.user|mysql\.db|mysql\.tables_priv)\b)",
            r"(\b(?:pg_user|pg_shadow|pg_group|pg_database)\b)",
            r"(\b(?:sqlite_master|sqlite_temp_master)\b)",
            
            # Comment variations
            r"(--[\s\r\n]|--$)",
            r"(\/\*[\s\S]*?\*\/)",
            r"(\#[\s\r\n]|\#$)",
            r"(;%00)",
            
            # Encoding bypasses
            r"(%27|%22|%23|%2D%2D|%2F%2A|%2A%2F)",
            r"(\%(?:20|09|0A|0D)(?:OR|AND|SELECT|UNION)\b)",
            
            # Advanced evasion techniques
            r"(\bSELECT\s+[\w\s,]*\s+FROM\s+[\w\s,()]*WHERE)",
            r"(\bINSERT\s+INTO\s+[\w\s]*\s+(?:VALUES|\(SELECT))",
            r"(\bUPDATE\s+[\w\s]*\s+SET\s+[\w\s=,]*WHERE)",
            r"(\bDELETE\s+FROM\s+[\w\s]*WHERE)"
        ]
        
        # Ultra Advanced XSS Patterns
        self.xss_patterns = [
            # Temel script tag'leri
            r"(<script[^>]*>[\s\S]*?</script>)",
            r"(<script[^>]*/>)",
            r"(<script[^>]*>[^<]*(?:(?!</script>)<[^<]*)*</script>)",
            
            # Gelişmiş iframe ve object tag'leri
            r"(<iframe[^>]*(?:src|srcdoc)[^>]*>[\s\S]*?</iframe>)",
            r"(<object[^>]*(?:data|type)[^>]*>[\s\S]*?</object>)",
            r"(<embed[^>]*(?:src|type)[^>]*>)",
            r"(<applet[^>]*(?:code|archive)[^>]*>[\s\S]*?</applet>)",
            
            # Meta ve link tag saldırıları
            r"(<meta[^>]*(?:http-equiv|content)[^>]*>)",
            r"(<link[^>]*(?:href|import)[^>]*>)",
            r"(<base[^>]*href[^>]*>)",
            
            # Style-based injection
            r"(<style[^>]*>[\s\S]*?(?:expression|javascript|vbscript|@import|behavior)[\s\S]*?</style>)",
            r"(style\s*=\s*['\"][^'\"]*(?:expression|javascript|vbscript|@import|behavior)[^'\"]*['\"])",
            
            # Event handler saldırıları (kapsamlı)
            r"(\bon(?:load|error|click|mouseover|mouseout|focus|blur|change|submit|reset|select|keyup|keydown|keypress|mousedown|mouseup|dblclick|contextmenu|wheel|scroll|resize|beforeunload|unload|hashchange|popstate|storage|online|offline|message|dragstart|drag|dragover|drop|cut|copy|paste|beforecopy|beforecut|beforepaste|selectstart|animationstart|animationend|transitionend)\s*=)",
            
            # JavaScript protokol saldırıları
            r"((?:href|src|action|formaction|poster|cite|background|longdesc|profile|usemap|classid|codebase|data|archive)\s*=\s*['\"]?\s*javascript:)",
            r"((?:href|src|action|formaction|poster|cite|background|longdesc|profile|usemap|classid|codebase|data|archive)\s*=\s*['\"]?\s*vbscript:)",
            r"((?:href|src|action|formaction|poster|cite|background|longdesc|profile|usemap|classid|codebase|data|archive)\s*=\s*['\"]?\s*livescript:)",
            
            # Data URI saldırıları
            r"(data:\s*(?:text/html|application/javascript|text/javascript|application/x-javascript)[^,]*,)",
            r"(data:\s*[^,]*base64\s*,[A-Za-z0-9+/=]*(?:script|eval|alert|prompt|confirm))",
            
            # HTML5 yeni tag'leri
            r"(<video[^>]*(?:poster|src)[^>]*>)",
            r"(<audio[^>]*src[^>]*>)",
            r"(<source[^>]*src[^>]*>)",
            r"(<track[^>]*src[^>]*>)",
            
            # SVG-based XSS
            r"(<svg[^>]*>[\s\S]*?(?:onload|onerror|onclick|onmouseover|script)[\s\S]*?</svg>)",
            r"(<svg[^>]*(?:onload|onerror|onclick|onmouseover)[^>]*>)",
            
            # Form-based saldırılar
            r"(<form[^>]*(?:action|formaction)[^>]*javascript:)",
            r"(<input[^>]*(?:onfocus|onblur|onchange|onclick|onselect)[^>]*>)",
            r"(<button[^>]*(?:onclick|onmouseover|onfocus)[^>]*>)",
            
            # CSS-based saldırılar
            r"(expression\s*\([^)]*\))",
            r"(@import\s*['\"]?[^'\"]*javascript:)",
            r"(behavior\s*:\s*url\s*\([^)]*\))",
            r"(-moz-binding\s*:\s*url\s*\([^)]*\))",
            
            # JavaScript fonksiyon çağrıları
            r"(\b(?:eval|setTimeout|setInterval|Function|execScript|msWriteProfilerMark)\s*\()",
            r"(\b(?:document\.write|document\.writeln|innerHTML|outerHTML)\s*[=\(])",
            r"(\b(?:window\.location|document\.location|location\.href|location\.replace|location\.assign)\s*[=\(])",
            
            # Template ve framework saldırıları
            r"(\{\{[^}]*(?:constructor|__proto__|prototype)[^}]*\}\})",
            r"(\[\[.*?(?:constructor|__proto__|prototype).*?\]\])",
            r"(<\?[^?]*(?:echo|print|eval)[^?]*\?>)",
            
            # Encoding bypass teknikleri
            r"(%3[Cc]script|%3[Ee]script|%2[Ff]script)",
            r"(&lt;script|&gt;script|&#x3c;script|&#60;script)",
            r"(\u003cscript|\u003e|\u0022|\u0027)",
            
            # Filter evasion
            r"(scr\x00ipt|java\x00script|vb\x00script)",
            r"(scr\nipt|java\nscript|on\nload)",
            r"(scr\tipt|java\tscript|on\tload)",
            
            # Advanced payload patterns
            r"(\[object\s+(?:HTMLImageElement|HTMLScriptElement|HTMLIFrameElement)\])",
            r"(toString\s*\(\s*\)\s*(?:\[|\.))",
            r"(String\s*\.\s*fromCharCode\s*\()",
            r"(unescape\s*\(|decodeURI\s*\(|decodeURIComponent\s*\()"
        ]
        
        # NoSQL Injection (MongoDB, CouchDB, etc.)
        self.nosql_patterns = [
            r"(\$(?:where|regex|ne|gt|lt|gte|lte|in|nin|exists|type|mod|all|size|elemMatch|slice|comment))",
            r"(\$(?:or|and|not|nor))",
            r"(this\.[\w\.]+)",
            r"(function\s*\(\s*\)\s*\{)",
            r"(ObjectId\s*\(\s*['\"][^'\"]*['\"]\s*\))",
            r"(db\.[\w]+\.(?:find|update|remove|drop|insert))",
            r"(sleep\s*\(\s*\d+\s*\))",
            r"(benchmark\s*\(\s*\d+)",
            r"(\$(?:unwind|match|group|sort|limit|skip|project|lookup|facet|bucket|bucketAuto|collStats|currentOp|indexStats|listLocalSessions|listSessions|planCacheClear|planCacheListFilters|planCacheListPlans|planCacheListQueryShapes|planCacheSetFilter))",
        ]
        
        # LDAP Injection
        self.ldap_patterns = [
            r"(\*\)|\(\*)",
            r"(\)\(|\(\))",
            r"(\|\(|\)\|)",
            r"(&\(|\)&)",
            r"(!\(|\)!)",
            r"(\(\w*\*\w*\))",
            r"(\(\w*=\*\))",
            r"(\(\|\(\w*=\w*\)\(\w*=\w*\)\))",
            r"(\(\&\(\w*=\w*\)\(\w*=\w*\)\))",
            r"(\(![\(\w=\*\)]*\))",
        ]
        
        # Advanced Command Injection
        self.command_patterns = [
            r"(;\s*(?:cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|tftp|nslookup|dig|host|mount|umount|df|du|free|top|htop|kill|killall|pkill|chmod|chown|chgrp|su|sudo|passwd|useradd|userdel|groupadd|groupdel)\b)",
            r"(\|\s*(?:cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|tftp|nslookup|dig|host|mount|umount|df|du|free|top|htop|kill|killall|pkill|chmod|chown|chgrp|su|sudo|passwd|useradd|userdel|groupadd|groupdel)\b)",
            r"(&\s*(?:cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|tftp|nslookup|dig|host|mount|umount|df|du|free|top|htop|kill|killall|pkill|chmod|chown|chgrp|su|sudo|passwd|useradd|userdel|groupadd|groupdel)\b)",
            r"(`[^`]*(?:cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|tftp|nslookup|dig|host|mount|umount|df|du|free|top|htop|kill|killall|pkill|chmod|chown|chgrp|su|sudo|passwd|useradd|userdel|groupadd|groupdel)[^`]*`)",
            r"(\$\([^)]*(?:cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|tftp|nslookup|dig|host|mount|umount|df|du|free|top|htop|kill|killall|pkill|chmod|chown|chgrp|su|sudo|passwd|useradd|userdel|groupadd|groupdel)[^)]*\))",
            r"(\${[^}]*(?:cat|ls|pwd|whoami|id|uname|ps|netstat|ifconfig|ping|wget|curl|nc|telnet|ssh|ftp|tftp|nslookup|dig|host|mount|umount|df|du|free|top|htop|kill|killall|pkill|chmod|chown|chgrp|su|sudo|passwd|useradd|userdel|groupadd|groupdel)[^}]*})",
            r"(\b(?:eval|exec|system|shell_exec|passthru|popen|proc_open|shell|pcntl_exec)\s*\()",
            r"(>\s*[/\\].*?(?:passwd|shadow|group|hosts|fstab|crontab|authorized_keys))",
            r"(<\s*[/\\].*?(?:passwd|shadow|group|hosts|fstab|crontab|authorized_keys))",
            r"(>>\s*[/\\].*?(?:passwd|shadow|group|hosts|fstab|crontab|authorized_keys))",
        ]
        
        # Path Traversal (LFI/RFI)
        self.path_traversal_patterns = [
            r"(\.\.[\//\\])",
            r"(%2e%2e[\//\\]|%2e%2e%2f|%2e%2e%5c)",
            r"(\.\.%2f|\.\.%5c|\.\.%c0%af|\.\.%c1%9c)",
            r"(%2e%2e\/|%2e%2e\\)",
            r"([\//\\]etc[\//\\]passwd)",
            r"([\//\\]windows[\//\\]system32[\//\\])",
            r"([\//\\]proc[\//\\]self[\//\\]environ)",
            r"([\//\\]var[\//\\]log[\//\\])",
            r"([\//\\]tmp[\//\\])",
            r"([\//\\]boot[\//\\])",
            r"([\//\\]sys[\//\\])",
            r"([\//\\]home[\//\\][\w]+[\//\\]\.ssh[\//\\])",
            r"([\//\\]root[\//\\]\.ssh[\//\\])",
            r"(php:[\//\\]{2}(?:filter|input|output|fd|memory|temp|glob))",
            r"(file:[\//\\]{2}[^\s]*)",
            r"(expect:[\//\\]{2}[^\s]*)",
            r"(data:[\//\\]{2}[^\s]*)",
            r"(http:[\//\\]{2}[^\s]*\.(?:txt|log|conf|ini|php|asp|jsp))",
            r"(ftp:[\//\\]{2}[^\s]*\.(?:txt|log|conf|ini|php|asp|jsp))",
        ]
        
        # Server-Side Template Injection (Ultra Advanced)
        self.ssti_patterns = [
            # Jinja2, Twig, Nunjucks
            r"(\{\{.*?(?:config|self|request|session|g|url_for|get_flashed_messages|lipsum|cycler|joiner|namespace).*?\}\})",
            r"(\{\{.*?(?:\.__class__|\.mro\(\)|\.subclasses\(\)|\.globals|\.builtins|\.import__).*?\}\})",
            r"(\{\{.*?(?:7\*7|49|lipsum\.__globals__|cycler\.__init__\.__globals__).*?\}\})",
            r"(\{%.*?(?:import|include|extends|macro|call|filter|set|for|if|with|autoescape).*?%\})",
            
            # Handlebars, Mustache
            r"(\{\{.*?(?:\#each|\#if|\#unless|\#with|\.\.\/|this\.|@root|@index).*?\}\})",
            r"(\{\{\{.*?(?:lookup|log|blockHelperMissing|helperMissing).*?\}\}\})",
            # Tüm template engine'leri kapsayan pattern
            r"(\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\}|\[#.*?\]|\{.*?\}|th:.*?=)",
            r"\{\{.*\}\}",
            # Freemarker, Velocity
            r"(<#.*?(?:import|include|assign|global|local|macro|function|if|list|switch).*?>)",
            r"(\$\{.*?(?:class|getClass|forName|newInstance).*?\})",
            r"(#set\s*\(\s*\$\w+\s*=\s*.+?\))",
            r"(#if\s*\(.*?\))",
            r"(#foreach\s*\(.*?\))",
            r"[\{\}\$\[\]#%@\\]|(\{\{|\}\}|\{%|%\}|\$\{|\[#|\])"
            # Smarty, Tpl
            r"(\{\{.*?\}\}|\{%.*?%\}|\$\{.*?\})"
            r"[\+\-\*/\%\^]"
            r"(\{.*?(?:\$smarty|\$_GET|\$_POST|\$_SESSION|\$_COOKIE|\$_SERVER|\$GLOBALS).*?\})",
            r"(\{.*?(?:assign|include|include_php|eval|fetch|config_load).*?\})",
            
            # Spring Expression Language (SpEL)
            r"(\$\{.*?(?:T\(|new\s+|@|#this|#root|systemProperties|systemEnvironment).*?\})",
            r"(\#\{.*?(?:T\(|new\s+|@|#this|#root|systemProperties|systemEnvironment).*?\})",
            
            # Ruby ERB
            r"(<%.*?(?:system|exec|eval|load|require|open|\`|\|).*?%>)",
            r"(<%=.*?(?:system|exec|eval|load|require|open|\`|\|).*?%>)",
            
            # Python f-strings and format
            r"(\{.*?(?:\.__class__|\.mro\(\)|\.subclasses\(\)|\.globals|\.builtins|\.import__|exec|eval|open|input|compile).*?\})",
            
            # Template bypass techniques
            r"(\{\{.*?(?:7\*7|\[\]|length|keys|values|items|pop|append|extend|insert|remove|reverse|sort|count|index).*?\}\})",
            r"(\{\{.*?(?:\|safe|\|raw|\|escape|\|e|\|striptags|\|length|\|list|\|string|\|int|\|float).*?\}\})",
        ]
        
        # XXE (XML External Entity) - Ultra Comprehensive
        self.xxe_patterns = [
            r"(<!ENTITY\s+\w+\s+SYSTEM\s+[\"'][^\"']*[\"'])",
            r"(<!ENTITY\s+\w+\s+PUBLIC\s+[\"'][^\"']*[\"']\s+[\"'][^\"']*[\"'])",
            r"(&\w+;)",
            r"(<!DOCTYPE[^>]*\[[\s\S]*?\]>)",
            r"(SYSTEM\s+[\"'](?:file|http|https|ftp|php|expect|data|zip|jar|netdoc|gopher):[^\"']*[\"'])",
            r"(PUBLIC\s+[\"'][^\"']*[\"']\s+[\"'](?:file|http|https|ftp|php|expect|data|zip|jar|netdoc|gopher):[^\"']*[\"'])",
            r"(<!ENTITY\s+%\s*\w+\s+SYSTEM\s+[\"'][^\"']*[\"']\s*>)",
            r"(<!ENTITY\s+%\s*\w+\s+[\"'][^\"']*[\"']\s*>)",
            r"(%\w+;)",
            r"(<\?xml\s+version\s*=\s*[\"'][^\"']*[\"']\s+encoding\s*=\s*[\"'][^\"']*[\"']\s*\?>)",
            r"(<!ELEMENT\s+\w+\s+(?:EMPTY|\([\w\s,|*+?()]+\)|ANY)>)",
            r"(<!ATTLIST\s+\w+\s+[\w\s]+>)",
            r"(<!ENTITY\s+\w+\s+[\"'][^\"']*[\"']\s*>)",  # Genel entity tanımları
            r"(<!ENTITY\s+%\s*\w+\s+PUBLIC\s+[\"'][^\"']*[\"']\s+[\"'][^\"']*[\"']\s*>)",  # Parametrik PUBLIC entity
            r"(&[a-zA-Z_][\w.-]*;)",  # Daha spesifik entity referansları
            r"(%[a-zA-Z_][\w.-]*;)",  # Parametrik entity referansları
            r"(SYSTEM\s+[\"'](?:ldap|mailto|news|nntp|telnet|dict|sftp|tftp|ssh):[^\"']*[\"'])",  # Ek protokoller
            r"(<!ENTITY\s+\w+\s+NDATA\s+\w+\s*>)",  # NDATA entity tanımları
            r"(<!NOTATION\s+\w+\s+(?:SYSTEM|PUBLIC)\s+[\"'][^\"']*[\"']\s*(?:\s+[\"'][^\"']*[\"'])?\s*>)",  # NOTATION tanımları
            r"(SYSTEM\s+[\"']\\\\[^\"']*[\"'])",  # Windows dosya yolları (UNC)
            r"(SYSTEM\s+[\"']/[^\"']*[\"'])",  # Unix/Linux dosya yolları
            r"(SYSTEM\s+[\"'][A-Za-z]:[^\"']*[\"'])",  # Windows sürücü yolları
            r"(<!DOCTYPE\s+\w+\s+SYSTEM\s+[\"'][^\"']*[\"']\s*>)",  # External DTD referansları
            r"(<!DOCTYPE\s+\w+\s+PUBLIC\s+[\"'][^\"']*[\"']\s+[\"'][^\"']*[\"']\s*>)",  # PUBLIC DTD
            r"(<!ENTITY\s+\w+\s+SYSTEM\s+[\"'][^\"']*[\"']\s+NDATA\s+\w+\s*>)",  # SYSTEM + NDATA
            r"(<!ENTITY\s+\w+\s+PUBLIC\s+[\"'][^\"']*[\"']\s+[\"'][^\"']*[\"']\s+NDATA\s+\w+\s*>)",  # PUBLIC + NDATA
            r"(\]\s*>[\s\S]*?&\w+;)",  # DTD sonrası entity kullanımı
            r"(<!ENTITY\s+\w+\s+[\"'][\s\S]*?&\w+;[\s\S]*?[\"']\s*>)",  # İç içe entity referansları
            r"(SYSTEM\s+[\"'](?:wrapper|compress\.zlib|compress\.bzip2|php://input|php://filter):[^\"']*[\"'])",  # PHP wrapper'ları
            r"(SYSTEM\s+[\"'](?:phar|ogg|rar):[^\"']*[\"'])",  # Diğer wrapper protokolleri
            r"(<!ENTITY\s+%\s*\w+\s+[\"'][\s\S]*?%\w+;[\s\S]*?[\"']\s*>)",  # Parametrik entity içinde entity ref
            r"(<!DOCTYPE[^>]*>\s*<[^>]*>&\w+;)",  # DOCTYPE sonrası hemen entity kullanımı
            r"(<!--[\s\S]*?<!ENTITY[\s\S]*?-->)",  # Yorum içinde gizlenmiş entity
            r"(<!\[CDATA\[[\s\S]*?<!ENTITY[\s\S]*?\]\]>)",  # CDATA içinde gizlenmiş entity
            r"(xmlns:xi\s*=\s*[\"']http://www\.w3\.org/2001/XInclude[\"'])",  # XInclude namespace
            r"(<xi:include\s+href\s*=\s*[\"'][^\"']*[\"'])",  # XInclude inclusion
            r"(<!ENTITY\s+\w+\s+[\"']&#x[0-9a-fA-F]+;[\"']\s*>)",  # Hex encoded entities
            r"(<!ENTITY\s+\w+\s+[\"']&#[0-9]+;[\"']\s*>)",  # Decimal encoded entities
            r"(&lt;!ENTITY)",  # HTML encoded entity declarations
            r"(&amp;\w+;)",  # HTML encoded entity references
            r"(SYSTEM\s+[\"']\.\.\/[^\"']*[\"'])",  # Directory traversal paths
            r"(SYSTEM\s+[\"'][^\"']*\?[^\"']*[\"'])",  # Query string içeren URL'ler
            r"(<!ENTITY\s+\w+\s+SYSTEM\s+[\"'][^\"']*[\"']\s*--[^>]*>)",  # Yorum ile karıştırılmış

        ]
        
        # Header Injection & HTTP Response Splitting
        self.header_patterns = [
            r"(\r\n(?:Set-Cookie|Location|Content-Type|Content-Length):|%0d%0a(?:Set-Cookie|Location|Content-Type|Content-Length):)",
            r"(\r\n\r\n|%0d%0a%0d%0a)",
            r"(\r\n(?:<script|<iframe|<object|<embed|<meta|<link)|%0d%0a(?:<script|<iframe|<object|<embed|<meta|<link))",
            r"(\n(?:Set-Cookie|Location|Content-Type|Content-Length):|%0a(?:Set-Cookie|Location|Content-Type|Content-Length):)",
            r"(\u000d\u000a(?:Set-Cookie|Location|Content-Type|Content-Length):)",
            r"(\u000a(?:Set-Cookie|Location|Content-Type|Content-Length):)",
        ]
        
        # Advanced Polyglot Patterns (Multiple attack vectors in one)
        self.polyglot_patterns = [
            r"(jaVasCript:[\s]*(?:\w+\s*\(|\w+\s*=|\w+\s*\[))",
            r"('><script>alert\((?:1|document\.domain|String\.fromCharCode)\)</script>)",
            r"(\"><script>alert\((?:1|document\.domain|String\.fromCharCode)\)</script>)",
            r"(';alert\(String\.fromCharCode\(\d+(?:,\d+)*\)\);//)",
            r"(\";alert\(String\.fromCharCode\(\d+(?:,\d+)*\)\);//)",
            r"(javascript:alert\((?:1|document\.domain|String\.fromCharCode)\))",
            r"(\\\";alert\((?:1|document\.domain)\);//)",
            r"(\\';alert\((?:1|document\.domain)\);//)",
            r"(\x3cscript\x3ealert\(1\)\x3c/script\x3e)",
            r"(&lt;script&gt;alert\(1\)&lt;/script&gt;)",
            r"(&#x3c;script&#x3e;alert\(1\)&#x3c;/script&#x3e;)",
            r"(&#60;script&#62;alert\(1\)&#60;/script&#62;)",
        ]
        
        # Binary/File Upload Attack Patterns
        self.file_upload_patterns = [
            r"(\x50\x4B\x03\x04.*?\.(?:php|asp|aspx|jsp|jspx))",  # ZIP with executable
            r"(\xFF\xD8\xFF.*?<\?php)",  # JPEG with PHP
            r"(\x89PNG.*?<\?php)",  # PNG with PHP
            r"(GIF8[79]a.*?<\?php)",  # GIF with PHP
            r"(\x25PDF.*?<script)",  # PDF with script
            r"(\x00\x00\x00\x18ftypmp4.*?<script)",  # MP4 with script
        ]
        # Unknown Patterns(for all patterns and not categorized)
        self.unknown_patterns = [
              # ==================== CSRF & SSRF PATTERNS ====================
    # Cross-Site Request Forgery
    r"(<form[^>]*action\s*=\s*['\"]?https?://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0))[^'\">\s]+['\"]?[^>]*>)",
    r"(<img[^>]*src\s*=\s*['\"]?https?://[^'\">\s]+(?:\?|&)[^'\">\s]*['\"]?[^>]*>)",
    r"(\$\.(?:post|get|ajax|load)\s*\(\s*['\"]?https?://[^'\"]*['\"]?)",
    r"(fetch\s*\(\s*['\"]?https?://[^'\"]*['\"]?)",
    r"(XMLHttpRequest.*?open\s*\(\s*['\"](?:GET|POST)['\"]?\s*,\s*['\"]?https?://[^'\"]*['\"]?)",
    
    # Server-Side Request Forgery (SSRF)
    r"((?:file|dict|sftp|ldap|tftp|gopher|jar|netdoc|mailto|news|imap|telnet|ssh)://[^\s\"'<>]+)",
    r"(https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|169\.254\.|::1|0000::|fc00:|fe80:)[^\s\"'<>]*)",
    r"(https?://[^\s\"'<>]*[@][^\s\"'<>]*)",
    r"(https?://[^\s\"'<>]*[:#][0-9]+[^\s\"'<>]*)",
    
    # ==================== ADVANCED DESERIALIZATION ====================
    # PHP Object Injection
    r"(O:\d+:[\"'][^\"']*[\"']:\d+:\{.*?\})",
    r"(a:\d+:\{.*?[\"']__wakeup[\"'].*?\})",
    r"(C:\d+:[\"'][^\"']*[\"']:\d+:\{.*?\})",
    r"(O:\+?\d+:[\"'][^\"']*[\"']:\d+:\{.*?s:\d+:[\"'].*?[\"'];O:\d+:)",
    
    # Java Deserialization
    r"(\xac\xed\x00\x05)",  # Java serialization magic number
    r"(rO0ABX[A-Za-z0-9+/=]+)",  # Base64 encoded Java object
    r"(\$\{jndi:(?:ldap|rmi|dns|nis|iiop|corba|nds|http)://[^\}]+\})",
    
    # .NET Deserialization
    r"(AAEAAAD/////AQAAAAAAAAAMAQAAAFdTeXN0ZW0p)",
    r"(<ObjectDataProvider[^>]*MethodName\s*=\s*[\"'][^\"']*[\"'][^>]*>)",
    r"(<XamlReader[^>]*Parse[^>]*>)",
    
    # Python Pickle
    r"(\x80\x03]q\x00)",  # Pickle protocol 3
    r"(\x80\x02]q\x00)",  # Pickle protocol 2
    r"(cos\n(?:system|eval|exec|open|compile|__import__)\n)",
    r"(c__builtin__\n(?:eval|exec|open|compile|__import__)\n)",
    
    # ==================== RACE CONDITIONS & TIMING ATTACKS ====================
    r"(sleep\s*\(\s*['\"]?\d+\.?\d*['\"]?\s*\))",
    r"(usleep\s*\(\s*['\"]?\d+['\"]?\s*\))",
    r"(time\.sleep\s*\(\s*['\"]?\d+\.?\d*['\"]?\s*\))",
    r"(Thread\.sleep\s*\(\s*['\"]?\d+['\"]?\s*\))",
    r"(setTimeout\s*\(\s*[^,]*,\s*['\"]?\d+['\"]?\s*\))",
    r"(setInterval\s*\(\s*[^,]*,\s*['\"]?\d+['\"]?\s*\))",
    
    # ==================== ADVANCED CRYPTOGRAPHIC ATTACKS ====================
    # Weak Crypto
    r"(\b(?:md5|sha1|des|3des|rc4|base64_encode)\s*\()",
    r"(\b(?:MD5|SHA1|DES|TripleDES|RC4|ROT13)\b)",
    r"(password\s*=\s*['\"][^'\"]{1,8}['\"])",  # Weak passwords
    r"(key\s*=\s*['\"][^'\"]{1,16}['\"])",  # Weak encryption keys
    r"(iv\s*=\s*['\"](?:0{16,}|1{16,}|[a]{16,})['\"])",  # Weak IVs
    
    # Hash Length Extension
    r"(hash_hmac\s*\(\s*['\"](?:md5|sha1)['\"])",
    r"(\$_(?:GET|POST|REQUEST|COOKIE)\[[^]]*\]\s*\.\s*['\"][^'\"]*['\"])",
    
    # ==================== API & OAUTH ATTACKS ====================
    # OAuth/JWT vulnerabilities
    r"(Bearer\s+[A-Za-z0-9\-._~+/]+=*)",
    r"(client_secret\s*=\s*['\"][^'\"]*['\"])",
    r"(access_token\s*=\s*['\"][^'\"]*['\"])",
    r"(refresh_token\s*=\s*['\"][^'\"]*['\"])",
    r"(\{[^}]*[\"']alg[\"']\s*:\s*[\"']none[\"'][^}]*\})",  # JWT alg:none
    r"(eyJ[A-Za-z0-9\-_]*\.eyJ[A-Za-z0-9\-_]*\.)",  # JWT structure
    
    # API Key exposure
    r"((?:api[_-]?key|apikey|secret[_-]?key|private[_-]?key|access[_-]?key)\s*[=:]\s*['\"][^'\"]+['\"])",
    r"((?:aws[_-]?access[_-]?key|aws[_-]?secret)\s*[=:]\s*['\"][^'\"]+['\"])",
    r"((?:google[_-]?api[_-]?key|firebase[_-]?key)\s*[=:]\s*['\"][^'\"]+['\"])",
    
    # ==================== ADVANCED XSS EVASIONS ====================
    # Unicode & Encoding bypasses
    r"(\u003c\u0073\u0063\u0072\u0069\u0070\u0074)",  # Unicode script
    r"(\u0022\u003e\u003c\u0073\u0063\u0072\u0069\u0070\u0074)",
    r"(\&\#x[0-9a-fA-F]+\;)",  # Hex entities
    r"(\&\#[0-9]+\;)",  # Decimal entities
    r"(%u[0-9a-fA-F]{4})",  # Unicode URL encoding
    
    # CSS-based XSS
    r"(@import[^;]*url\s*\([^)]*javascript:[^)]*\))",
    r"(background(?:-image)?\s*:\s*url\s*\([^)]*javascript:[^)]*\))",
    r"(content\s*:\s*[^;]*javascript:[^;]*)",
    r"(-webkit-transform\s*:\s*[^;]*javascript:[^;]*)",
    
    # SVG Advanced XSS
    r"(<svg[^>]*><foreignObject[^>]*><div[^>]*onclick[^>]*>)",
    r"(<svg[^>]*><animateTransform[^>]*onbegin[^>]*>)",
    r"(<svg[^>]*><set[^>]*onload[^>]*>)",
    r"(<svg[^>]*><animate[^>]*onrepeat[^>]*>)",
    
    # ==================== BUSINESS LOGIC BYPASSES ====================
    # Price manipulation
    r"(price\s*[=:]\s*-?\d*\.?\d+)",
    r"(amount\s*[=:]\s*-?\d*\.?\d+)",
    r"(quantity\s*[=:]\s*-?\d*\.?\d+)",
    r"(discount\s*[=:]\s*-?\d*\.?\d+)",
    
    # User role manipulation
    r"((?:is_admin|admin|role|permission|privilege)\s*[=:]\s*(?:true|1|admin|root))",
    r"(user_id\s*[=:]\s*\d+)",
    r"(group_id\s*[=:]\s*\d+)",
    
    # ==================== MEMORY CORRUPTION ====================
    # Buffer overflow patterns
    r"([Aa]{100,}|[Bb]{100,}|[Cc]{100,}|[Xx]{100,})",
    r"(%[0-9a-fA-F]{2}){100,}",
    r"(\x41{100,}|\x42{100,}|\x43{100,}|\x90{10,})",  # NOP sleds
    
    # Format string attacks
    r"(%[0-9]*[dioxXeEfFgGaAcspn%]){4,}",
    r"(%[0-9]*\$[dioxXeEfFgGaAcspn])",
    r"(%[0-9]+x%[0-9]+\$n)",
    
    # ==================== MOBILE & APP SPECIFIC ====================
    # Android Intent injection
    r"(intent://[^#]*#Intent;[^;]*;end)",
    r"(android\.intent\.action\.[A-Z_]+)",
    r"(content://[^/]*/[^/]*)",
    
    # iOS URL scheme abuse
    r"([a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>\"']*)",
    r"(cydia://[^\s<>\"']*)",
    r"(itms-services://[^\s<>\"']*)",
    
    # ==================== CLOUD & CONTAINER ATTACKS ====================
    # Docker escapes
    r"(docker\s+(?:run|exec|cp|commit)\s+[^;]*(?:--privileged|--cap-add|--security-opt|--pid=host|--net=host|--ipc=host))",
    r"(/proc/self/cgroup|/sys/fs/cgroup)",
    r"(/var/run/docker\.sock)",
    
    # Kubernetes attacks
    r"(kubectl\s+(?:exec|cp|proxy|port-forward)\s+)",
    r"(/var/run/secrets/kubernetes\.io/serviceaccount)",
    r"(ServiceAccount|ClusterRole|ClusterRoleBinding)",
    
    # AWS/Cloud metadata
    r"(169\.254\.169\.254/latest/meta-data)",
    r"(metadata\.google\.internal/computeMetadata)",
    r"(100\.100\.100\.200/latest/meta-data)",  # Alibaba Cloud
    
    # ==================== ADVANCED LOG INJECTION ====================
    r"(\r\n[^:]*:\s*[^:]*(?:ERROR|WARN|FATAL|DEBUG))",
    r"(%0d%0a[^:]*:\s*[^:]*(?:ERROR|WARN|FATAL|DEBUG))",
    r"(\n\[\d{4}-\d{2}-\d{2}[^]]*\]\s*(?:ERROR|WARN|FATAL))",
    r"(\u0000.*?(?:admin|root|system|kernel))",
    
    # ==================== PROTOCOL ATTACKS ====================
    # HTTP Request Smuggling
    r"(Transfer-Encoding:\s*chunked.*?Content-Length:\s*\d+)",
    r"(Content-Length:\s*\d+.*?Transfer-Encoding:\s*chunked)",
    r"(\r\n0\r\n\r\nGET\s+/)",
    r"(\r\n0\r\n\r\nPOST\s+/)",
    
    # WebSocket injection
    r"(Sec-WebSocket-Key:\s*[^=]*={0,2}[^A-Za-z0-9+/=])",
    r"(Sec-WebSocket-Protocol:\s*[^,]*[<>\"'&])",
    
    # ==================== AI/ML SPECIFIC ATTACKS ====================
    # Prompt injection
    r"(ignore\s+(?:previous|all|above)\s+(?:instructions|prompts|commands))",
    r"(system:\s*you\s+are\s+now\s+)",
    r"(override\s+(?:safety|security|guidelines|rules))",
    r"(\[SYSTEM\]\s*[^[]*\[/SYSTEM\])",
    
    # Model extraction
    r"(print\s*\(\s*model\.state_dict\(\s*\)\s*\))",
    r"(torch\.save\s*\(\s*model)",
    r"(pickle\.dump\s*\(\s*model)",
    
    # ==================== BLOCKCHAIN & CRYPTO ====================
    # Smart contract attacks
    r"(selfdestruct\s*\(\s*[^)]*\))",
    r"(delegatecall\s*\(\s*[^)]*\))",
    r"(call\.value\s*\(\s*[^)]*\))",
    r"(tx\.origin\s*==)",
    
    # Cryptocurrency addresses (for monitoring)
    r"([13][a-km-zA-HJ-NP-Z1-9]{25,34})",  # Bitcoin
    r"(0x[a-fA-F0-9]{40})",  # Ethereum
    
    # ==================== ADVANCED STEGANOGRAPHY ====================
    # Hidden data in images
    r"(data:image/[^;]*;base64,[A-Za-z0-9+/]*=*.*?<script)",
    r"(\xFF\xFE.*?<script|\xFE\xFF.*?<script)",  # BOM + script
    r"(\x00.*?(?:eval|exec|system).*?\x00)",  # Null-byte injection
    
    # ==================== BIOMETRIC & AUTHENTICATION BYPASS ====================
    r"(fingerprint\s*[=:]\s*['\"][^'\"]*['\"])",
    r"(biometric\s*[=:]\s*(?:true|false|1|0))",
    r"(two_factor\s*[=:]\s*(?:false|0|disabled))",
    r"(mfa\s*[=:]\s*(?:false|0|disabled))",
    
    # ==================== QUANTUM COMPUTING THREATS ====================
    # Post-quantum crypto indicators
    r"(\b(?:RSA|DSA|ECDSA|ECDH)\b.*?(?:1024|2048))",  # Weak key sizes
    r"(\b(?:sike|ntru|frodo|dilithium|falcon|sphincs)\b)",  # PQC algorithms
    
    # ==================== ZERO-DAY INDICATORS ====================
    # Unusual function combinations
    r"(eval\s*\(\s*(?:atob|btoa|String\.fromCharCode|unescape)\s*\([^)]*\)\s*\))",
    r"(exec\s*\(\s*(?:base64_decode|gzuncompress|rot13|str_rot13)\s*\([^)]*\)\s*\))",
    r"((?:system|shell_exec|passthru)\s*\(\s*(?:base64_decode|hex2bin|gzuncompress)\s*\([^)]*\)\s*\))",
    
    # ==================== IOT & EMBEDDED ATTACKS ====================
    r"(/dev/(?:ttyS|ttyUSB|ttyACM|i2c|spi)[0-9]*)",
    r"(AT\+[A-Z]+[=?]?[^;]*)",  # AT commands
    r"(UART|I2C|SPI|GPIO.*?(?:read|write|toggle))",
    
    # ==================== SUPPLY CHAIN ATTACKS ====================
    r"(npm\s+install\s+[^@]*@[^/]*\.(?:tgz|tar\.gz))",
    r"(pip\s+install\s+[^-]*-[^-]*\.(?:whl|tar\.gz))",
    r"(<script[^>]*src\s*=\s*[\"'][^\"']*(?:unpkg|jsdelivr|cdnjs)[^\"']*[\"'][^>]*>)",
    
    # ==================== DARK WEB & TOR ====================
    r"([a-z2-7]{16}\.onion)",  # Tor hidden services
    r"(torsocks|proxychains|torify)",
    
    # ==================== SOCIAL ENGINEERING ====================
    r"((?:password|username|email|phone).*?(?:reset|recovery|verification|confirm))",
    r"(click\s+here\s+to\s+(?:verify|confirm|activate|reset))",
    r"(urgent.*?(?:action|response|verification)\s+required)",
    
    # ==================== EXOTIC ENCODINGS ====================
    r"(\x1b\[[0-9;]*[mK])",  # ANSI escape codes
    r"(\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\[0-7]{3})",  # Escape sequences
    r"(=\?[^?]*\?[BQ]\?[^?]*\?=)",  # MIME encoded words
    
    # ==================== ADVANCED PERSISTENCE ====================
    r"((?:autorun|autostart|startup)\.inf)",
    r"(HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\.*?(?:Run|RunOnce|Startup))",
    r"(/etc/(?:rc\.local|init\.d|systemd/system|cron))",
    r"(\$HOME/\.(?:bashrc|profile|zshrc|vimrc))",
    
    # ==================== NETWORK PIVOTING ====================
    r"((?:ssh|nc|ncat|socat)\s+.*?-[Ll]\s+\d+)",  # Port forwarding
    r"(sshuttle|chisel|ligolo|reGeorg)",
    r"(SOCKS[45]?.*?proxy)",
    
    # ==================== DATA EXFILTRATION ====================
    r"((?:curl|wget|nc|ncat)\s+.*?\|\s*(?:base64|xxd|od))",
    r"(dns\s+(?:query|lookup).*?\|\s*(?:base64|hex))",
    r"(icmp\s+.*?data\s*=\s*[A-Za-z0-9+/=]{20,})",
    
    # ==================== MALWARE SIGNATURES ====================
    r"(\x4d\x5a\x90\x00)",  # PE header
    r"(\x7f\x45\x4c\x46)",  # ELF header
    r"(\xca\xfe\xba\xbe)",  # Java class file
    r"(\x50\x4b\x03\x04.*?\.(?:exe|scr|bat|com|pif))",  # ZIP with executables
    
    # ==================== ADVANCED REGEX BYPASSES ====================
    r"(\/\*[\s\S]*?\*\/|\/\/[^\r\n]*|--[^\r\n]*|#[^\r\n]*)",  # Comments
    r"(\w+\s*=\s*\w+\s*\+\s*['\"][^'\"]*['\"])",  # String concatenation
    r"(String\s*\.\s*(?:join|concat|format)\s*\([^)]*\))",
    r"(charAt\s*\(\s*\d+\s*\)\s*\+)",  # Character building
    
    # ==================== CRITICAL SYSTEM FILES ====================
    r"(/etc/(?:passwd|shadow|group|sudoers|hosts|fstab|crontab|ssh/ssh_config|ssh/sshd_config))",
    r"(/root/\.(?:ssh/authorized_keys|bash_history|vimrc))",
    r"(/var/log/(?:auth\.log|secure|messages|syslog|lastlog|wtmp|btmp))",
    r"(/proc/(?:version|cpuinfo|meminfo|mounts|net/arp|self/environ|self/cmdline))",
    r"(C:\\(?:Windows\\System32|Users\\[^\\]*\\AppData|Program Files))",
    
    # ==================== SANDBOX ESCAPES ====================
    r"(\\\\\.\\pipe\\[^\\]*)",  # Named pipes
    r"(/tmp/\.(?:X11-unix|ICE-unix)/)",
    r"(chroot\s+[^;]*;)",
    r"(unshare\s+.*?(?:--pid|--net|--mount|--user))",
    
    # ==================== ULTRA RARE ATTACKS ====================
    # Rowhammer-like memory attacks
    r"(memset\s*\(\s*[^,]*,\s*0x[0-9a-fA-F]+,\s*\d{6,}\s*\))",
    
    # Side-channel attacks
    r"(performance\.now\s*\(\s*\).*?performance\.now\s*\(\s*\))",
    r"(Date\.now\s*\(\s*\).*?Date\.now\s*\(\s*\))",
    
    # Advanced timing attacks
    r"(for\s*\(\s*[^;]*;\s*[^;]*<\s*\d{6,}\s*;\s*[^;]*\)\s*\{\s*\})",
    
    # Hardware-level attacks
    r"(/dev/(?:mem|kmem|port|urandom|hwrng|tpm0))",
    r"(/sys/(?:class/gpio|bus/i2c|kernel/debug))",
    
    # ==================== FINAL EXOTIC PATTERNS ====================
    # Esoteric programming languages
    r"(brainfuck|malbolge|piet|whitespace|ook)",
    r"([+\-<>\[\].,]{20,})",  # Brainfuck-like
    
    # Steganographic text
    r"((?:[A-Z]{2,}\s+){5,})",  # Hidden messages in caps
    r"((?:\u200b|\u200c|\u200d|\u2060|\ufeff)+)",  # Zero-width characters
    
    # Unicode homograph attacks
    r"((?:а|е|о|р|с|х|у|А|Е|О|Р|С|Х|У))",  # Cyrillic lookalikes
    r"((?:⁄|∕|⧸|⧹))",  # Various slash characters
    
    # Final catch-all for unknown threats
    r"([\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F])",  # Control characters
    r"([^\x20-\x7E\xA0-\xFF]{3,})",  # Non-printable sequences
    # Whitespace evasion
    r"(\w+\s{2,}\w+)",
    r"(\w+[\t\r\n]+\w+)",
    
    # Case manipulation
    r"([A-Z]{1}[a-z]+[A-Z]{1}[a-z]+)",  # CamelCase evasion
    r"([a-z]+[A-Z]+[a-z]+[A-Z]+)",
    
    # Mixed encoding
    r"(%[0-9a-fA-F]{2}.*?&#\d+;.*?\\u[0-9a-fA-F]{4})",
    
    # String building
    r"(String\s*\.\s*fromCharCode\s*\(\s*\d+(?:\s*,\s*\d+){3,}\s*\))",
    r"(chr\s*\(\s*\d+\s*\)\s*\.?\s*chr\s*\(\s*\d+\s*\))",
    
    # Obfuscation
    r"((?:[A-Za-z0-9+/]{4})*[A-Za-z0-9+/]{2,3}={0,2}.*?(?:eval|exec|system))",  # Base64 + dangerous
    r"(\\x[0-9a-fA-F]{2}.*?\\x[0-9a-fA-F]{2}.*?\\x[0-9a-fA-F]{2})",  # Hex encoding chains
        ]
        
        # Combine all patterns
        self.all_patterns = (
            self.sql_patterns + self.xss_patterns + self.nosql_patterns +
            self.ldap_patterns + self.command_patterns + self.path_traversal_patterns +
            self.ssti_patterns + self.xxe_patterns + self.header_patterns +
            self.polyglot_patterns + self.file_upload_patterns + self.unknown_patterns
        )
        
        # Compile patterns for performance
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.DOTALL | re.MULTILINE) for pattern in self.all_patterns]
        
        # Güvenli dosya uzantıları ve content type'lar
        self.safe_extensions = {'.css', '.js', '.html', '.htm', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map'}
        self.safe_content_types = {
            'text/css', 'text/javascript', 'application/javascript', 'text/html', 
            'image/png', 'image/jpeg', 'image/gif', 'image/svg+xml', 
            'application/font-woff', 'font/woff2', 'font/ttf', 'application/font-sfnt'
        }
        
        # Threat intelligence patterns
        self.malware_signatures = [
            r"(c99|r57|WSO|FilesMan|SafeMode|Bypass|phpinfo|system|passthru|shell_exec|exec|eval|base64_decode)",
            r"(WScript\.Shell|cmd\.exe|powershell\.exe|/bin/sh|/bin/bash)",
            r"(nc\s+-.*?-e|netcat.*?-e|socat|cryptcat)",
        ]
        
        # Rate limiting settings
        self.rate_limits = {
            'requests_per_minute': 60,
            'requests_per_hour': 1000,
            'max_request_size': 10 * 1024 * 1024,  # 10MB
            'suspicious_threshold': 10,
            'ban_duration': 3600,  # 1 hour
        }

    def is_safe_request(self, request):
        """Enhanced safe request detection"""
        path = request.path.lower()
        
        # Check file extensions
        for ext in self.safe_extensions:
            if path.endswith(ext):
                return True
        
        # Check static/media paths
        if hasattr(settings, 'STATIC_URL') and settings.STATIC_URL:
            if path.startswith(settings.STATIC_URL.lower()):
                return True
        
        if hasattr(settings, 'MEDIA_URL') and settings.MEDIA_URL:
            if path.startswith(settings.MEDIA_URL.lower()):
                return True
        
        # Check if it's a known admin or API path that needs protection
        dangerous_paths = ['/admin/', '/api/', '/graphql/', '/upload/', '/file/', '/download/']
        for dangerous_path in dangerous_paths:
            if path.startswith(dangerous_path):
                return False
        
        return False

    def get_client_ip(self, request):
        """Get real client IP with proxy support"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
            return ip
        except:
            return request.META.get('REMOTE_ADDR', '0.0.0.0')

    def is_rate_limited(self, request):
        """Advanced rate limiting with IP reputation"""
        client_ip = self.get_client_ip(request)
        current_time = time.time()
        
        # Check if IP is already blocked
        if client_ip in self.blocked_ips:
            return True
        
        # Clean old requests
        self.request_counts[client_ip] = deque([
            req_time for req_time in self.request_counts[client_ip]
            if current_time - req_time < 3600  # Keep requests from last hour
        ])
        
        # Add current request
        self.request_counts[client_ip].append(current_time)
        
        # Check rate limits
        recent_requests = len([
            req_time for req_time in self.request_counts[client_ip]
            if current_time - req_time < 60  # Last minute
        ])
        
        hourly_requests = len(self.request_counts[client_ip])
        
        # Apply rate limits
        if recent_requests > self.rate_limits['requests_per_minute']:
            self.suspicious_ips[client_ip] += 5
            logger.warning(f"Rate limit exceeded (per minute) for IP: {client_ip}")
            return True
        
        if hourly_requests > self.rate_limits['requests_per_hour']:
            self.suspicious_ips[client_ip] += 10
            logger.warning(f"Rate limit exceeded (per hour) for IP: {client_ip}")
            return True
        
        # Check suspicious behavior
        if self.suspicious_ips[client_ip] > self.rate_limits['suspicious_threshold']:
            self.blocked_ips.add(client_ip)
            logger.error(f"IP blocked due to suspicious activity: {client_ip}")
            return True
        
        return False

    def advanced_decode(self, data_str):
        """Advanced decoding with multiple encoding types"""
        if not data_str:
            return [data_str]
        
        decoded_variants = [data_str]
        
        try:
            # URL decoding variants
            decoded_variants.append(urllib.parse.unquote(data_str))
            decoded_variants.append(urllib.parse.unquote_plus(data_str))
            
            # Double encoding
            double_decoded = urllib.parse.unquote(urllib.parse.unquote(data_str))
            decoded_variants.append(double_decoded)
            
            # HTML entity decoding
            html_decoded = data_str.replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&amp;', '&').replace('&#x27;', "'").replace('&#x2F;', '/')
            decoded_variants.append(html_decoded)
            
            # Unicode normalization
            import unicodedata
            normalized = unicodedata.normalize('NFKD', data_str)
            decoded_variants.append(normalized)
            
            # Base64 detection and decoding
            import base64
            if len(data_str) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]*={0,2}$', data_str):
                try:
                    b64_decoded = base64.b64decode(data_str).decode('utf-8', errors='ignore')
                    decoded_variants.append(b64_decoded)
                except:
                    pass
            
            # Hexadecimal decoding
            if re.match(r'^[0-9a-fA-F]+$', data_str) and len(data_str) % 2 == 0:
                try:
                    hex_decoded = bytes.fromhex(data_str).decode('utf-8', errors='ignore')
                    decoded_variants.append(hex_decoded)
                except:
                    pass
                    
        except Exception as e:
            logger.debug(f"Decoding error: {e}")
        
        return list(set(decoded_variants))  # Remove duplicates

    def check_injection(self, data_str):
        """Ultra advanced injection detection"""
        if not data_str:
            return False, None, 0
        
        # Get all decoded variants
        decoded_variants = self.advanced_decode(data_str)
        
        threat_score = 0
        detected_patterns = []
        
        for data_variant in decoded_variants:
            if not data_variant:
                continue
                
            # Check against all compiled patterns
            for i, pattern in enumerate(self.compiled_patterns):
                matches = pattern.findall(data_variant)
                if matches:
                    # Weight different attack types
                    if i < len(self.sql_patterns):
                        threat_score += 10  # SQL injection is critical
                        detected_patterns.append(f"SQL:{pattern.pattern}")
                    elif i < len(self.sql_patterns) + len(self.xss_patterns):
                        threat_score += 8  # XSS is high risk
                        detected_patterns.append(f"XSS:{pattern.pattern}")
                    elif i < len(self.sql_patterns) + len(self.xss_patterns) + len(self.command_patterns):
                        threat_score += 15  # Command injection is critical
                        detected_patterns.append(f"CMD:{pattern.pattern}")
                    else:
                        threat_score += 5  # Other attacks
                        detected_patterns.append(f"OTHER:{pattern.pattern}")
        
        # Additional heuristic checks
        if len(data_str) > 10000:  # Unusually long input
            threat_score += 2
        
        if data_str.count('<') > 10 or data_str.count('>') > 10:  # Many HTML tags
            threat_score += 3
        
        if data_str.count('(') > 20 or data_str.count(')') > 20:  # Many function calls
            threat_score += 3
        
        if len(re.findall(r'["\']', data_str)) > 20:  # Many quotes
            threat_score += 2
        
        # Check for malware signatures
        for signature in self.malware_signatures:
            if re.search(signature, data_str, re.IGNORECASE):
                threat_score += 20
                detected_patterns.append(f"MALWARE:{signature}")
        
        return threat_score > 5, detected_patterns, threat_score

    def analyze_request_patterns(self, request):
        """Deep request pattern analysis"""
        suspicious_patterns = []
        client_ip = self.get_client_ip(request)
        
        # Check for common attack patterns in headers
        dangerous_headers = [
            'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_X_ORIGINATING_IP',
            'HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_USER_AGENT',
            'HTTP_REFERER', 'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE'
        ]
        
        for header in dangerous_headers:
            if header in request.META:
                value = request.META[header]
                is_malicious, patterns, score = self.check_injection(value)
                if is_malicious:
                    suspicious_patterns.extend(patterns)
        
        # Check request method abuse
        if request.method in ['TRACE', 'TRACK', 'DEBUG', 'OPTIONS']:
            suspicious_patterns.append(f"DANGEROUS_METHOD:{request.method}")
        
        # Check for suspicious User-Agent patterns
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        suspicious_ua_patterns = [
            r'sqlmap', r'nikto', r'nessus', r'burp', r'w3af', r'acunetix',
            r'netsparker', r'webscarab', r'paros', r'havij', r'dirbuster',
            r'dirb', r'gobuster', r'wfuzz', r'ffuf', r'masscan', r'nmap'
        ]
        
        for ua_pattern in suspicious_ua_patterns:
            if re.search(ua_pattern, user_agent, re.IGNORECASE):
                suspicious_patterns.append(f"SUSPICIOUS_UA:{ua_pattern}")
                self.suspicious_ips[client_ip] += 5
        
        return suspicious_patterns

    def scan_request_data(self, request):
        """Comprehensive request data scanning"""
        malicious_data = []
        client_ip = self.get_client_ip(request)
        
        # Analyze request patterns first
        pattern_analysis = self.analyze_request_patterns(request)
        if pattern_analysis:
            malicious_data.extend([{
                'type': 'PATTERN_ANALYSIS',
                'key': 'suspicious_patterns',
                'value': str(pattern_analysis),
                'threat_score': len(pattern_analysis) * 2
            }])
        
        # Scan GET parameters
        for key, value in request.GET.items():
            is_malicious, patterns, score = self.check_injection(f"{key}={value}")
            if is_malicious:
                malicious_data.append({
                    'type': 'GET',
                    'key': key,
                    'value': value[:500] + '...' if len(value) > 500 else value,
                    'patterns': patterns,
                    'threat_score': score
                })
                self.suspicious_ips[client_ip] += score // 5
        
        # Scan POST parameters
        if hasattr(request, 'POST'):
            for key, value in request.POST.items():
                is_malicious, patterns, score = self.check_injection(f"{key}={value}")
                if is_malicious:
                    malicious_data.append({
                        'type': 'POST',
                        'key': key,
                        'value': value[:500] + '...' if len(value) > 500 else value,
                        'patterns': patterns,
                        'threat_score': score
                    })
                    self.suspicious_ips[client_ip] += score // 5
        
        # Scan headers
        for header_name, header_value in request.META.items():
            if header_name.startswith('HTTP_'):
                is_malicious, patterns, score = self.check_injection(f"{header_name}={header_value}")
                if is_malicious:
                    malicious_data.append({
                        'type': 'HEADER',
                        'key': header_name,
                        'value': header_value[:200] + '...' if len(header_value) > 200 else header_value,
                        'patterns': patterns,
                        'threat_score': score
                    })
                    self.suspicious_ips[client_ip] += score // 10
        
        # Scan request body
        if hasattr(request, 'body') and request.body:
            try:
                if len(request.body) > self.rate_limits['max_request_size']:
                    malicious_data.append({
                        'type': 'OVERSIZED_REQUEST',
                        'key': 'body_size',
                        'value': f"{len(request.body)} bytes",
                        'threat_score': 10
                    })
                else:
                    body_str = request.body.decode('utf-8', errors='ignore')
                    is_malicious, patterns, score = self.check_injection(body_str)
                    if is_malicious:
                        malicious_data.append({
                            'type': 'BODY',
                            'key': 'raw_body',
                            'value': body_str[:500] + '...' if len(body_str) > 500 else body_str,
                            'patterns': patterns,
                            'threat_score': score
                        })
                        self.suspicious_ips[client_ip] += score // 5
            except Exception as e:
                logger.debug(f"Body scanning error: {e}")
        
        # Scan cookies
        for cookie_name, cookie_value in request.COOKIES.items():
            is_malicious, patterns, score = self.check_injection(f"{cookie_name}={cookie_value}")
            if is_malicious:
                malicious_data.append({
                    'type': 'COOKIE',
                    'key': cookie_name,
                    'value': cookie_value[:200] + '...' if len(cookie_value) > 200 else cookie_value,
                    'patterns': patterns,
                    'threat_score': score
                })
                self.suspicious_ips[client_ip] += score // 10
        
        return malicious_data

    def create_honeypot_response(self, request):
        """Create honeypot response for attackers"""
        client_ip = self.get_client_ip(request)
        self.honeypot_triggers.add(client_ip)
        
        # Log detailed attack information
        logger.critical(f"HONEYPOT TRIGGERED - Advanced attack detected from {client_ip}")
        
        # Return fake vulnerable response to waste attacker's time
        fake_responses = [
            "MySQL Error: You have an error in your SQL syntax",
            "Warning: mysql_fetch_array() expects parameter 1 to be resource",
            "Fatal error: Call to undefined function",
            "Parse error: syntax error, unexpected",
        ]
        
        import random
        fake_error = random.choice(fake_responses)
        return HttpResponseBadRequest(fake_error)

    def process_request(self, request):
        """Main request processing with ultra security"""
        client_ip = self.get_client_ip(request)
        
        # Skip safe requests
        if self.is_safe_request(request):
            return None
        
        # Check rate limiting
        if self.is_rate_limited(request):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return HttpResponseForbidden('Rate limit exceeded')
        
        # Scan for malicious content
        malicious_data = self.scan_request_data(request)
        
        if malicious_data:
            # Calculate total threat score
            total_threat = sum(item.get('threat_score', 0) for item in malicious_data)
            
            # Log attack details
            logger.error(
                f"SECURITY VIOLATION DETECTED - IP: {client_ip}, "
                f"Path: {request.path}, Method: {request.method}, "
                f"Threat Score: {total_threat}, Details: {malicious_data}"
            )
            
            # Create attack fingerprint for tracking
            attack_data = f"{client_ip}{request.path}{request.method}"
            attack_hash = hashlib.sha256(attack_data.encode()).hexdigest()[:16]
            
            # Store attack in cache for tracking
            cache_key = f"security_attack_{attack_hash}"
            cache.set(cache_key, {
                'ip': client_ip,
                'timestamp': time.time(),
                'threat_score': total_threat,
                'details': malicious_data
            }, 86400)  # 24 hours
            
            # Determine response based on threat level
            if total_threat > 50:  # Critical threat
                self.blocked_ips.add(client_ip)
                return self.create_honeypot_response(request)
            elif total_threat > 20:  # High threat
                self.suspicious_ips[client_ip] += 10
                if getattr(settings, 'DEBUG', False):
                    return JsonResponse({
                        'error': 'Critical security violation detected',
                        'attack_id': attack_hash,
                        'threat_score': total_threat,
                        'blocked': True
                    }, status=403)
                else:
                    return HttpResponseForbidden('Access denied')
            else:  # Medium threat
                self.suspicious_ips[client_ip] += 5
                if getattr(settings, 'DEBUG', False):
                    return JsonResponse({
                        'error': 'Security violation detected',
                        'attack_id': attack_hash,
                        'threat_score': total_threat,
                        'details': malicious_data
                    }, status=400)
                else:
                    return HttpResponseBadRequest('Invalid request')
        
        return None

    def process_response(self, request, response):
        """Enhanced response processing with security headers"""
        if self.is_safe_request(request):
            return response
        
        # Add comprehensive security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response['X-Permitted-Cross-Domain-Policies'] = 'none'
        response['X-Download-Options'] = 'noopen'
        response['X-DNS-Prefetch-Control'] = 'off'
        response['Expect-CT'] = 'max-age=86400, enforce'
        response['Feature-Policy'] = (
            "accelerometer 'none'; camera 'none'; geolocation 'none'; "
            "gyroscope 'none'; magnetometer 'none'; microphone 'none'; "
            "payment 'none'; usb 'none'"
        )
        
        # Enhanced CSP
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "media-src 'self'; "
            "object-src 'none'; "
            "child-src 'none'; "
            "worker-src 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "manifest-src 'self';"
        )
        response['Content-Security-Policy'] = csp_policy
        
        # Add custom security headers
        response['X-Security-Middleware'] = 'ComprehensiveSecurityMiddleware/2.0'
        response['X-Attack-Protection'] = 'active'
        
        return response
  

logger = logging.getLogger(__name__)

class SecurityEmailNotificationMiddleware(MiddlewareMixin):
    """
    Güvenlik saldırısı tespit edildiğinde anında e-posta bildirimi gönderen middleware
    IP geolocation bilgileri ile geliştirilmiş versiyon - Maximum bilgi toplama
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        
       # E-posta ayarları - settings.py'den al veya varsayılan değerleri kullan
        self.smtp_server = getattr(settings, 'SECURITY_EMAIL_SMTP_SERVER', " ")  # SMTP sunucu
        self.smtp_port = getattr(settings, 'SECURITY_EMAIL_SMTP_PORT', )  # SSL portu 
        self.sender_email = getattr(settings, 'SECURITY_EMAIL_SENDER', " ") # Gönderen email adresi
        self.sender_password = getattr(settings, 'SECURITY_EMAIL_PASSWORD', "") # Göneren email adresinin şifresi(gmail adresi ise uygulama şifresi)
        self.recipient_email = getattr(settings, 'SECURITY_EMAIL_RECIPIENT', "") # Maili Alan email adresi

        
        # E-posta gönderme aktif mi?
        self.email_enabled = getattr(settings, 'SECURITY_EMAIL_ENABLED', True)
        
        # IP-API ayarları
        self.ip_api_enabled = getattr(settings, 'IP_GEOLOCATION_ENABLED', True)
        self.ip_api_timeout = getattr(settings, 'IP_API_TIMEOUT', 8)  # Timeout artırıldı
        
        # Saldırı türlerini tanımla
        self.attack_types = {
            'SQL_INJECTION': {
                'name': 'SQL Injection Saldırısı',
                'description': 'Veritabanına zararlı SQL sorguları gönderme girişimi',
                'severity': 'YÜKSEK', 
                'icon': '💉'
            },
            'XSS': {
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'Zararlı JavaScript kodu enjekte etme girişimi',
                'severity': 'YÜKSEK',
                'icon': '🕷️'
            },
            'COMMAND_INJECTION': {
                'name': 'Komut Enjeksiyonu',
                'description': 'Sistem komutları çalıştırma girişimi',
                'severity': 'KRİTİK',
                'icon': '⚡'
            },
            'PATH_TRAVERSAL': {
                'name': 'Dizin Geçiş Saldırısı',
                'description': 'Sistem dosyalarına erişim girişimi',
                'severity': 'YÜKSEK',
                'icon': '📁'
            },
            'NOSQL_INJECTION': {
                'name': 'NoSQL Injection',
                'description': 'MongoDB veya benzeri veritabanlarına özel sorgu enjeksiyonu girişimi',
                'severity': 'YÜKSEK',
                'icon': '🧬'
            },
            'LDAP_INJECTION': {
                'name': 'LDAP Injection',
                'description': 'LDAP sorgularını manipüle ederek yetkisiz erişim sağlama girişimi',
                'severity': 'YÜKSEK',
                'icon': '📚'
            },
            'SSTI': {
                'name': 'Server-Side Template Injection (SSTI)',
                'description': 'Sunucu taraflı şablon motorlarını manipüle etme girişimi',
                'severity': 'KRİTİK',
                'icon': '🧩'
            },
            'XXE': {
                'name': 'XML External Entity (XXE)',
                'description': 'XML işleyicilerini kullanarak iç sistem bilgilerine erişim sağlama girişimi',
                'severity': 'YÜKSEK',
                'icon': '📦'
            },
            'HEADER_INJECTION': {
                'name': 'HTTP Header Injection',
                'description': 'HTTP başlıklarını enjekte ederek yönlendirme veya veri sızdırma girişimi',
                'severity': 'ORTA',
                'icon': '🧾'
            },
            'RATE_LIMIT': {
                'name': 'Rate Limit Aşımı',
                'description': 'Çok fazla istek gönderme girişimi',
                'severity': 'ORTA',
                'icon': '🚦'
            },
            'BRUTEFORCE': {
                'name': 'Brute Force Saldırısı',
                'description': 'Şifre kırma veya yetkisiz erişim girişimi',
                'severity': 'YÜKSEK',
                'icon': '🔨'
            },
            'UNKNOWN': {
                'name': 'Bilinmeyen Saldırı',
                'description': 'Tanımlanmamış güvenlik tehdidi',
                'severity': 'ORTA',
                'icon': '❓'
            }
        }

        self.smtp_server = ""  # Smtp serveri
        self.smtp_port = 465  # SSL portu
        self.sender_email = "" # Yollayan mail adresi
        self.sender_password = os.environ.get('EMAIL_PASSWORD')


        # Saldırı tespiti için regex desenleri - compiled patterns for performance
        self.attack_patterns = {
            'SQL_INJECTION': [
                # UNION + SELECT birleşimi (en bilindik)
re.compile(r"\bUNION\s+SELECT\b", re.IGNORECASE),
    # Temel SQL işlemleri ve FROM kullanımı
re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b\s+[\w\*,\s]+\s+\bFROM\b", re.IGNORECASE),
    # Tehlikeli komut zincirleri (Windows/MSSQL)
re.compile(r"\b(xp_cmdshell|sp_executesql|exec(?:\s|\+))\b", re.IGNORECASE),
    # SQL fonksiyonları ve schema'lar
re.compile(r"\b(INFORMATION_SCHEMA|sysobjects|syscolumns)\b", re.IGNORECASE),
    # Mantıksal bypass örnekleri (tuned for precision)
re.compile(r"\b(OR|AND)\b\s*\(?\s*['\"]?\w+['\"]?\s*(=|LIKE)\s*['\"]?\w+['\"]?\s*\)?", re.IGNORECASE),
re.compile(r"\b(OR|AND)\b\s*\(?\s*\d+\s*=\s*\d+\s*\)?", re.IGNORECASE),
    # UNION tekrar (gizli bypasslar için farklı varyasyon)
re.compile(r"\bUNION\s+ALL\s+SELECT\b", re.IGNORECASE),
    # SLEEP / WAIT saldırıları (time-based)
re.compile(r"\bWAITFOR\s+DELAY\b", re.IGNORECASE),
re.compile(r"\bSLEEP\s*\(\s*\d+\s*\)", re.IGNORECASE),
    # Tip dönüşümleri
re.compile(r"\b(CONVERT|CAST)\s*\(", re.IGNORECASE),
    # String oluşturma ve kod gizleme
re.compile(r"\bCHAR\s*\(\s*\d+\s*\)", re.IGNORECASE),
re.compile(r"\b(CONCATENATE|CONCAT)\b", re.IGNORECASE),
    # Metin parçalayıcı fonksiyonlar
re.compile(r"\b(SUBSTRING|MID|LEFT|RIGHT)\b", re.IGNORECASE),
    # HAVING filtre zafiyeti
re.compile(r"\bHAVING\s+\d+\s*=\s*\d+", re.IGNORECASE),
    
    # Comment-based bypass'lar
re.compile(r"--[\s\S]*", re.IGNORECASE),  # SQL comment
re.compile(r"/\*.*?\*/", re.DOTALL | re.IGNORECASE),  # Multi-line comment
re.compile(r"#[\s\S]*", re.IGNORECASE),  # MySQL comment
    
    # SQL tırnak bypass teknikleri
re.compile(r"['\"];?\s*(OR|AND|UNION)", re.IGNORECASE),
re.compile(r"['\"][\s]*\+[\s]*['\"]", re.IGNORECASE),  # String concatenation
    
    # Blind SQL injection kalıpları
re.compile(r"\b(OR|AND)\s+\d+\s*[<>]=?\s*\d+", re.IGNORECASE),
re.compile(r"\b(OR|AND)\s+['\"]?[a-zA-Z]+['\"]?\s*[<>]=?\s*['\"]?[a-zA-Z]+['\"]?", re.IGNORECASE),
    
    # Boolean-based blind SQL injection
re.compile(r"\b(TRUE|FALSE)\b\s*(AND|OR)", re.IGNORECASE),
re.compile(r"\b(OR|AND)\s+(TRUE|FALSE)\b", re.IGNORECASE),
    
    # Time-based blind SQL injection (ek)
re.compile(r"\bBENCHMARK\s*\(\s*\d+", re.IGNORECASE),  # MySQL
re.compile(r"\bpg_sleep\s*\(\s*\d+\s*\)", re.IGNORECASE),  # PostgreSQL
    
    # Database version ve bilgi toplama
re.compile(r"\b(@@VERSION|VERSION\(\)|@@SERVERNAME)\b", re.IGNORECASE),
re.compile(r"\b(USER\(\)|CURRENT_USER|SESSION_USER)\b", re.IGNORECASE),
re.compile(r"\b(DATABASE\(\)|DB_NAME\(\))\b", re.IGNORECASE),
    
    # Error-based SQL injection
re.compile(r"\b(EXTRACTVALUE|UPDATEXML)\s*\(", re.IGNORECASE),  # MySQL
re.compile(r"\bUTL_INADDR\.", re.IGNORECASE),  # Oracle
    
    # Stacked queries
re.compile(r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)", re.IGNORECASE),
    
    # Schema enumeration
re.compile(r"\b(TABLE_SCHEMA|TABLE_NAME|COLUMN_NAME)\b", re.IGNORECASE),
re.compile(r"\bsys\.(tables|columns|databases)\b", re.IGNORECASE),
    
    # SQL functions commonly used in injections
re.compile(r"\b(COUNT|MAX|MIN|SUM|AVG)\s*\(", re.IGNORECASE),
re.compile(r"\b(ASCII|ORD|HEX|UNHEX)\s*\(", re.IGNORECASE),
re.compile(r"\b(LENGTH|LEN|CHAR_LENGTH)\s*\(", re.IGNORECASE),
    
    # Encoding bypass attempts
re.compile(r"\\x[0-9a-fA-F]{2}", re.IGNORECASE),  # Hex encoding
re.compile(r"%[0-9a-fA-F]{2}", re.IGNORECASE),  # URL encoding
re.compile(r"&#x?[0-9a-fA-F]+;", re.IGNORECASE),  # HTML entity encoding
    
    # NULL değer manipülasyonu
re.compile(r"\bIS\s+(NOT\s+)?NULL\b", re.IGNORECASE),
re.compile(r"\bISNULL\s*\(", re.IGNORECASE),
re.compile(r"\bCOALESCE\s*\(", re.IGNORECASE),
    
    # LIKE operatörü abuse
re.compile(r"\bLIKE\s+['\"]%", re.IGNORECASE),
re.compile(r"\bLIKE\s+['\"][^'\"]*[%_]", re.IGNORECASE),
    
    # SQL wildcard characters
re.compile(r"['\"][%_\*]['\"]", re.IGNORECASE),
    
    # DROP TABLE/DATABASE attempts
re.compile(r"\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b", re.IGNORECASE),
    
    # INSERT/CREATE attempts for privilege escalation
re.compile(r"\b(CREATE|ALTER)\s+(TABLE|DATABASE|USER|FUNCTION)\b", re.IGNORECASE),
    
    # File operations (MySQL/PostgreSQL)
re.compile(r"\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b", re.IGNORECASE),
re.compile(r"\bCOPY\s+.*\bFROM\b", re.IGNORECASE),  # PostgreSQL
    
    # Advanced union-based patterns
re.compile(r"\bUNION\s+(ALL\s+)?SELECT\s+NULL", re.IGNORECASE),
re.compile(r"\bUNION\s+(ALL\s+)?SELECT\s+\d+", re.IGNORECASE),
    
    # CASE WHEN statements (blind injection)
re.compile(r"\bCASE\s+WHEN\b", re.IGNORECASE),
    
    # IF statements (MySQL blind injection)
re.compile(r"\bIF\s*\(.*,.*,.*\)", re.IGNORECASE),
    
    # LIMIT/OFFSET bypass
re.compile(r"\bLIMIT\s+\d+\s*,\s*\d+", re.IGNORECASE),
re.compile(r"\bOFFSET\s+\d+", re.IGNORECASE),
    
    # ORDER BY column enumeration
re.compile(r"\bORDER\s+BY\s+\d+", re.IGNORECASE),
    
    # Multiple statement separators
re.compile(r";\s*--", re.IGNORECASE),
re.compile(r";\s*/\*", re.IGNORECASE),
    
    # Common bypass techniques
re.compile(r"\b(OR|AND)\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?", re.IGNORECASE),
re.compile(r"\b(OR|AND)\s+['\"]?0['\"]?\s*=\s*['\"]?0['\"]?", re.IGNORECASE),
re.compile(r"['\"][\s]*\|\|[\s]*['\"]", re.IGNORECASE),  # Concatenation operator
    
    # Special characters commonly used in SQLi
re.compile(r"['\"][\s]*\+[\s]*['\"]", re.IGNORECASE),
re.compile(r"['\"][\s]*&[\s]*['\"]", re.IGNORECASE),
            ],
            'XSS': [
    re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<.*?on\w+\s*=.*?>", re.IGNORECASE | re.DOTALL),
    re.compile(r"javascript\s*:", re.IGNORECASE),
            # Script tag varyasyonları
    re.compile(r"<script[^>]*>", re.IGNORECASE),  # Script açılış tagı
    re.compile(r"</script>", re.IGNORECASE),  # Script kapanış tagı
    re.compile(r"<script\s*>", re.IGNORECASE),  # Boş script tag
    re.compile(r"<script\s*/?>", re.IGNORECASE),  # Self-closing script
    
    # Iframe injections
    re.compile(r"<iframe.*?>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<iframe[^>]*src\s*=.*?>", re.IGNORECASE | re.DOTALL),
    
    # Object/Embed tags
    re.compile(r"<object.*?>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<embed.*?>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<applet.*?>", re.IGNORECASE | re.DOTALL),
    
    # Form ve input manipulation
    re.compile(r"<form.*?>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<input[^>]*type\s*=\s*[\"']?hidden[\"']?", re.IGNORECASE),
    
    # Meta refresh redirect
    re.compile(r"<meta[^>]*http-equiv\s*=\s*[\"']?refresh[\"']?", re.IGNORECASE),
    
    # Link tag exploits
    re.compile(r"<link[^>]*href\s*=\s*[\"']?javascript:", re.IGNORECASE),
    re.compile(r"<link[^>]*href\s*=\s*[\"']?data:", re.IGNORECASE),
    
    # Image tag XSS
    re.compile(r"<img[^>]*src\s*=\s*[\"']?javascript:", re.IGNORECASE),
    re.compile(r"<img[^>]*src\s*=\s*[\"']?data:", re.IGNORECASE),
    re.compile(r"<img[^>]*onerror\s*=", re.IGNORECASE),
    re.compile(r"<img[^>]*onload\s*=", re.IGNORECASE),
    
    # Style attribute XSS
    re.compile(r"style\s*=.*?expression\s*\(", re.IGNORECASE | re.DOTALL),
    re.compile(r"style\s*=.*?javascript\s*:", re.IGNORECASE | re.DOTALL),
    re.compile(r"style\s*=.*?-moz-binding\s*:", re.IGNORECASE | re.DOTALL),
    
    # CSS import XSS
    re.compile(r"@import\s+[\"']?javascript:", re.IGNORECASE),
    re.compile(r"@import\s+[\"']?data:", re.IGNORECASE),
    
    # Event handlers (kapsamlı liste)
    re.compile(r"on(abort|blur|change|click|dblclick|error|focus|keydown|keypress|keyup|load|mousedown|mousemove|mouseout|mouseover|mouseup|reset|resize|select|submit|unload)\s*=", re.IGNORECASE),
    re.compile(r"on(beforeunload|contextmenu|copy|cut|paste|beforeprint|afterprint|hashchange|message|offline|online|pagehide|pageshow|popstate|storage|wheel)\s*=", re.IGNORECASE),
    re.compile(r"on(animationend|animationiteration|animationstart|transitionend)\s*=", re.IGNORECASE),
    
    # Data URLs
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
    re.compile(r"data\s*:\s*application/javascript", re.IGNORECASE),
    re.compile(r"data\s*:\s*text/javascript", re.IGNORECASE),
    
    # JavaScript protocol variations
    re.compile(r"javascript\s*:\s*//", re.IGNORECASE),
    re.compile(r"j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:", re.IGNORECASE),  # Spaced
    re.compile(r"&#[x]?6[a]?;avascript:", re.IGNORECASE),  # HTML entity encoded
    
    # VBScript (IE)
    re.compile(r"vbscript\s*:", re.IGNORECASE),
    re.compile(r"livescript\s*:", re.IGNORECASE),
    
    # Encoding bypass attempts
    re.compile(r"&#x[0-9a-f]+;", re.IGNORECASE),  # Hex entities
    re.compile(r"&#[0-9]+;", re.IGNORECASE),  # Decimal entities
    re.compile(r"%[0-9a-f]{2}", re.IGNORECASE),  # URL encoding
    re.compile(r"\\u[0-9a-f]{4}", re.IGNORECASE),  # Unicode escape
    re.compile(r"\\x[0-9a-f]{2}", re.IGNORECASE),  # Hex escape
    
    # Base64 encoded payloads
    re.compile(r"data\s*:\s*[^;]*;\s*base64\s*,", re.IGNORECASE),
    
    # SVG XSS
    re.compile(r"<svg.*?>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<svg[^>]*onload\s*=", re.IGNORECASE),
    re.compile(r"<animateTransform[^>]*onbegin\s*=", re.IGNORECASE),
    
    # Audio/Video XSS
    re.compile(r"<audio[^>]*onloadstart\s*=", re.IGNORECASE),
    re.compile(r"<video[^>]*onloadstart\s*=", re.IGNORECASE),
    re.compile(r"<source[^>]*onerror\s*=", re.IGNORECASE),
    
    # Table XSS
    re.compile(r"<table[^>]*background\s*=\s*[\"']?javascript:", re.IGNORECASE),
    re.compile(r"<td[^>]*background\s*=\s*[\"']?javascript:", re.IGNORECASE),
    
    # Body tag XSS
    re.compile(r"<body[^>]*onload\s*=", re.IGNORECASE),
    re.compile(r"<body[^>]*onunload\s*=", re.IGNORECASE),
    re.compile(r"<body[^>]*background\s*=\s*[\"']?javascript:", re.IGNORECASE),
    
    # Marquee XSS
    re.compile(r"<marquee[^>]*onstart\s*=", re.IGNORECASE),
    re.compile(r"<marquee[^>]*onbounce\s*=", re.IGNORECASE),
    
    # CSS Expression (IE)
    re.compile(r"expression\s*\(.*?\)", re.IGNORECASE | re.DOTALL),
    
    # Comments with script content
    re.compile(r"<!--.*?<script.*?-->", re.IGNORECASE | re.DOTALL),
    re.compile(r"/\*.*?<script.*?\*/", re.IGNORECASE | re.DOTALL),
    
    # Font-face XSS
    re.compile(r"@font-face.*?src\s*:\s*url\s*\(\s*[\"']?javascript:", re.IGNORECASE | re.DOTALL),
    
    # Server-sent events
    re.compile(r"<eventsource[^>]*src\s*=", re.IGNORECASE),
    
    # WebSocket XSS
    re.compile(r"new\s+WebSocket\s*\(", re.IGNORECASE),
    
    # Eval and Function constructor
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"Function\s*\(.*?\)", re.IGNORECASE | re.DOTALL),
    re.compile(r"setTimeout\s*\(\s*[\"'][^\"']*[\"']\s*,", re.IGNORECASE),
    re.compile(r"setInterval\s*\(\s*[\"'][^\"']*[\"']\s*,", re.IGNORECASE),
    
    # Document methods
    re.compile(r"document\.(write|writeln|createElement)", re.IGNORECASE),
    re.compile(r"document\.location\s*=", re.IGNORECASE),
    re.compile(r"window\.location\s*=", re.IGNORECASE),
    
    # innerHTML assignments
    re.compile(r"\.innerHTML\s*=", re.IGNORECASE),
    re.compile(r"\.outerHTML\s*=", re.IGNORECASE),
    
    # String.fromCharCode obfuscation
    re.compile(r"String\.fromCharCode\s*\(", re.IGNORECASE),
    re.compile(r"fromCharCode\s*\(", re.IGNORECASE),
    
    # Template literals (ES6)
    re.compile(r"`.*?\$\{.*?\}.*?`", re.DOTALL),
    
    # Import statements
    re.compile(r"import\s*\(", re.IGNORECASE),
    re.compile(r"import\s+.*?\s+from\s+[\"']", re.IGNORECASE),
    
    # Worker XSS
    re.compile(r"new\s+Worker\s*\(", re.IGNORECASE),
    re.compile(r"new\s+SharedWorker\s*\(", re.IGNORECASE),
    
    # Fetch API
    re.compile(r"fetch\s*\(\s*[\"'][^\"']*javascript:", re.IGNORECASE),
    
    # Form action XSS
    re.compile(r"<form[^>]*action\s*=\s*[\"']?javascript:", re.IGNORECASE),
    
    # CDATA sections
    re.compile(r"<!\[CDATA\[.*?<script", re.IGNORECASE | re.DOTALL),
    
    # Attribute without quotes
    re.compile(r"\w+\s*=\s*javascript:", re.IGNORECASE),
    re.compile(r"\w+\s*=\s*data:", re.IGNORECASE),
            ],

            'COMMAND_INJECTION': [
 # Core template delimiters
    re.compile(r"\{\{.*?\}\}", re.IGNORECASE),                  # Jinja2 / Handlebars
    re.compile(r"\{%.*?%\}", re.IGNORECASE),                    # Jinja2 block
    re.compile(r"<%.*?%>", re.IGNORECASE),                      # ERB, ASP
    re.compile(r"\[\[.*?\]\]", re.IGNORECASE),                  # Angular
    re.compile(r"<#.*?>", re.IGNORECASE),                       # Freemarker directives
    re.compile(r"<@.*?/>", re.IGNORECASE),                      # Freemarker user directives
    
    # Template-specific syntax
    re.compile(r"\(@.*?@\)", re.IGNORECASE),                    # Razor
    re.compile(r"@\{.*?\}", re.IGNORECASE),                     # Razor
    re.compile(r"@\(.*?\)", re.IGNORECASE),                     # Razor expressions
    re.compile(r"\{\{\{.*?\}\}\}", re.IGNORECASE),              # Unescaped Handlebars
    re.compile(r"\{\{&.*?\}\}", re.IGNORECASE),                 # Unescaped Handlebars alt
    re.compile(r"\{\{!.*?\}\}", re.IGNORECASE),                 # Handlebars comments
    re.compile(r"\{\{#.*?\}\}", re.IGNORECASE),                 # Handlebars helpers
    re.compile(r"\{\{/.*?\}\}", re.IGNORECASE),                 # Handlebars closing
    re.compile(r"\{\{\^.*?\}\}", re.IGNORECASE),                # Handlebars inverted
    re.compile(r"\{\{>.*?\}\}", re.IGNORECASE),                 # Handlebars partials
    
    # === PYTHON-SPECIFIC SSTI PATTERNS ===
    
    # Python object introspection
    re.compile(r"\{\{.*?\.__class__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__mro__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__subclasses__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__globals__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__init__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__doc__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__module__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__dict__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__bases__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__import__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__builtins__.*?\}\}", re.IGNORECASE),
    
    # Flask/Jinja2 specific objects
    re.compile(r"\{\{.*?config.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?self.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?request.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?url_for.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?get_flashed_messages.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?session.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?g\..*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?cycler.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?joiner.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?namespace.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?lipsum.*?\}\}", re.IGNORECASE),
    
            ],
            'PATH_TRAVERSAL': [
            # Temel path traversal pattern'leri
    re.compile(r"(\.\./|\.\.\\)+", re.IGNORECASE),
    re.compile(r"(\.\.\/|\.\.\\)", re.IGNORECASE),
    
    # URL encoded versiyonlar
    re.compile(r"(%2e%2e%2f|%2e%2e%5c)", re.IGNORECASE),
    re.compile(r"(\.\.%2f|\.\.%5c)", re.IGNORECASE),
    re.compile(r"(%2e%2e\/|%2e%2e\\)", re.IGNORECASE),
    re.compile(r"(%2e%2e%2f|%2e%2e%5c)+", re.IGNORECASE),
    
    # Double URL encoding
    re.compile(r"(%252e%252e%252f|%252e%252e%255c)", re.IGNORECASE),
    re.compile(r"(%252e%252e\/|%252e%252e\\)", re.IGNORECASE),
    
    # UTF-8 encoding variations
    re.compile(r"(%c0%ae%c0%ae%2f|%c0%ae%c0%ae%5c)", re.IGNORECASE),
    re.compile(r"(%c1%9c|%c0%9v)", re.IGNORECASE),
    
    # 16-bit Unicode encoding
    re.compile(r"(%u002e%u002e%u002f|%u002e%u002e%u005c)", re.IGNORECASE),
    re.compile(r"(%u2216|%u2215)", re.IGNORECASE),
    
    # Mixed encoding combinations
    re.compile(r"(\.%2e\.|%2e\.%2e|%2e%2e\.)", re.IGNORECASE),
    re.compile(r"(\.\.%c0%af|\.\.%c1%9c)", re.IGNORECASE),
    
    # Null byte injection ile path traversal
    re.compile(r"(\.\./.*%00|\.\.\\.*%00)", re.IGNORECASE),
    re.compile(r"(%2e%2e%2f.*%00|%2e%2e%5c.*%00)", re.IGNORECASE),
    
    # Kritik sistem dosyaları (Linux/Unix)
    re.compile(r"(\/etc\/passwd|\/etc\/shadow|\/etc\/hosts)", re.IGNORECASE),
    re.compile(r"(\/etc\/group|\/etc\/fstab|\/etc\/crontab)", re.IGNORECASE),
    re.compile(r"(\/proc\/self\/environ|\/proc\/version|\/proc\/cmdline)", re.IGNORECASE),
    re.compile(r"(\/proc\/self\/fd\/|\/proc\/self\/maps)", re.IGNORECASE),
    re.compile(r"(\/var\/log\/|\/var\/www\/|\/var\/mail\/)", re.IGNORECASE),
    re.compile(r"(\/tmp\/|\/dev\/|\/mnt\/)", re.IGNORECASE),
    re.compile(r"(\/boot\/|\/sys\/|\/root\/)", re.IGNORECASE),
    re.compile(r"(\/home\/.*\/\.ssh\/|\/home\/.*\/\.bash_history)", re.IGNORECASE),
    
    
    # Farklı slash kombinasyonları
    re.compile(r"(\/\.\.\/|\\\.\.\\|\/\.\.\.|\\\.\.\.)", re.IGNORECASE),
    re.compile(r"(\/\.\.\.\.|\\\.\.\.\.)", re.IGNORECASE),
    
    # Path traversal with different separators
    re.compile(r"(\.\.\x2f|\.\.\x5c)", re.IGNORECASE),
    re.compile(r"(\x2e\x2e\x2f|\x2e\x2e\x5c)", re.IGNORECASE),
    
    # Alternative representations
    re.compile(r"(\.\.\/\.\.\/|\.\.\\\.\.\\)", re.IGNORECASE),
    re.compile(r"(\.\.;\/|\.\.;\\.)", re.IGNORECASE),
            ],
            'NOSQL_INJECTION': [
    # MongoDB Query Operators
    re.compile(r"(\$where|\$regex|\$ne|\$gt|\$lt|\$gte|\$lte|\$in|\$nin)", re.IGNORECASE),
    
    # MongoDB Update Operators
    re.compile(r"(\$set|\$unset|\$inc|\$push|\$pull|\$addToSet|\$pop|\$rename)", re.IGNORECASE),
    
    # MongoDB Aggregation Operators
    re.compile(r"(\$match|\$group|\$sort|\$limit|\$skip|\$project|\$lookup)", re.IGNORECASE),
    
    # MongoDB Evaluation Operators
    re.compile(r"(\$expr|\$jsonSchema|\$mod|\$text|\$geoIntersects|\$geoWithin)", re.IGNORECASE),
    
    # MongoDB Array Operators
    re.compile(r"(\$all|\$elemMatch|\$size|\$slice)", re.IGNORECASE),
    
    # MongoDB Logical Operators
    re.compile(r"(\$and|\$or|\$not|\$nor)", re.IGNORECASE),
    
    # JavaScript Injection Patterns
    re.compile(r"(function\s*\(|eval\s*\(|setTimeout\s*\(|setInterval\s*\()", re.IGNORECASE),
    
    # MongoDB-specific JavaScript functions
    re.compile(r"(ObjectId\s*\(|ISODate\s*\(|UUID\s*\(|BinData\s*\()", re.IGNORECASE),
    
    # Common NoSQL injection payloads
    re.compile(r"(\{\s*\$ne\s*:\s*null\s*\}|\{\s*\$regex\s*:\s*['\"].*['\"])", re.IGNORECASE),
    
    # MongoDB shell commands
    re.compile(r"(db\.|show\s+dbs|show\s+collections|use\s+\w+)", re.IGNORECASE),
    
    # CouchDB/Couchbase specific
    re.compile(r"(_design|_view|_all_docs|_bulk_docs|emit\s*\()", re.IGNORECASE),
    
    # Redis specific commands
    re.compile(r"(FLUSHDB|FLUSHALL|CONFIG|EVAL|SCRIPT)", re.IGNORECASE),
    
    # Cassandra/CQL specific
    re.compile(r"(DROP\s+KEYSPACE|CREATE\s+KEYSPACE|ALTER\s+TABLE)", re.IGNORECASE),
    
    # Generic NoSQL injection attempts
    re.compile(r"(\|\||&&|!=|==|\$\w+:)", re.IGNORECASE),
    
    # MongoDB error-based injection indicators
    re.compile(r"(MongoError|E11000|duplicate\s+key)", re.IGNORECASE),
    
    # Time-based injection patterns
    re.compile(r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)", re.IGNORECASE),
    
    # Boolean-based blind injection
    re.compile(r"(\$exists\s*:\s*(true|false|1|0))", re.IGNORECASE),
    
    # Advanced MongoDB operators
    re.compile(r"(\$type|\$bitsAllSet|\$bitsAnySet|\$bitsAllClear|\$bitsAnyClear)", re.IGNORECASE),
    
    # Geospatial operators
    re.compile(r"(\$near|\$nearSphere|\$geoNear|\$center|\$centerSphere)", re.IGNORECASE),
            ],
            'LDAP_INJECTION': [
            # Basic LDAP injection patterns
    re.compile(r"(\*\)|\(\*)", re.IGNORECASE),
    re.compile(r"(\)\(|\(\))", re.IGNORECASE),
    re.compile(r"(\|\(|\)\|)", re.IGNORECASE),
    re.compile(r"(&\(|\)&)", re.IGNORECASE),
    re.compile(r"(!\(|\)!)", re.IGNORECASE),
    re.compile(r"(\(\w*\*\w*\))", re.IGNORECASE),
    re.compile(r"(\(\w*=\*\))", re.IGNORECASE),
    re.compile(r"(\(\|\(\w*=\w*\)\(\w*=\w*\)\))", re.IGNORECASE),
    
    # Boolean-based blind injection
    re.compile(r"(\(\w*=.*\w*\)\(\w*=.*\w*\))", re.IGNORECASE),
    re.compile(r"(\(\&\(\w*=.*\)\(\w*=.*\)\))", re.IGNORECASE),
    
    # Wildcard-based injection
    re.compile(r"(\(\w*=.*\*.*\))", re.IGNORECASE),
    re.compile(r"(\(\w*=\*.*\w+.*\))", re.IGNORECASE),
    re.compile(r"(\(\w*=.*\w+.*\*\))", re.IGNORECASE),
    
    # Time-based injection patterns
    re.compile(r"(\(\w*>=\d{4}\))", re.IGNORECASE),
    re.compile(r"(\(\w*<=\d{4}\))", re.IGNORECASE),
    
    # Attribute existence testing
    re.compile(r"(\(\w*=\*\)\(\!\(\w*=\*\)\))", re.IGNORECASE),
    re.compile(r"(\(\w*\*\)\(\!\(\w*\*\)\))", re.IGNORECASE),
    
    # Common LDAP attributes abuse
    re.compile(r"(\(objectClass=\*\))", re.IGNORECASE),
    re.compile(r"(\(cn=\*\)|\(uid=\*\)|\(mail=\*\))", re.IGNORECASE),
    re.compile(r"(\(distinguishedName=\*\))", re.IGNORECASE),
    
    # Administrative bypass attempts
    re.compile(r"(\(userAccountControl=\*\))", re.IGNORECASE),
    re.compile(r"(\(memberOf=\*admin\*\))", re.IGNORECASE),
    re.compile(r"(\(sAMAccountName=\*\))", re.IGNORECASE),
    
    # Complex boolean logic injection
    re.compile(r"(\(\&\(\|\(.*\)\(.*\)\)\(\w*=.*\)\))", re.IGNORECASE),
    re.compile(r"(\(\|\(\&\(.*\)\(.*\)\)\(\w*=.*\)\))", re.IGNORECASE),
    
    # Nested filter injection
    re.compile(r"(\(\w*=.*\(\w*=.*\).*\))", re.IGNORECASE),
    re.compile(r"(\(\w*=.*\)\(\w*=.*\)\(\w*=.*\))", re.IGNORECASE),
    
    # Character encoding bypass attempts
    re.compile(r"(\\2A|\\28|\\29|\\7C|\\26|\\21)", re.IGNORECASE),  # *, (, ), |, &, !
    re.compile(r"(%2A|%28|%29|%7C|%26|%21)", re.IGNORECASE),
    
    # LDAP protocol exploitation
    re.compile(r"(\(\w*~=.*\))", re.IGNORECASE),  # Approximate match
    re.compile(r"(\(\w*:=.*\))", re.IGNORECASE),   # Extensible match
    
    # Directory traversal in LDAP
    re.compile(r"(\.\./|\.\\.)", re.IGNORECASE),
    re.compile(r"(dc=.*,dc=.*)", re.IGNORECASE),
    
    # LDAP bind bypass
    re.compile(r"(\(\w*=\)\(\w*=.*\))", re.IGNORECASE),
    re.compile(r"(\(\|\(\w*=\)\(\w*=.*\)\))", re.IGNORECASE),
    
    # Substring search manipulation
    re.compile(r"(\(\w*=.*\*.*\*.*\))", re.IGNORECASE),
    re.compile(r"(\(\w*=\*.*\*.*\*\))", re.IGNORECASE),
    
    # Comparison operators abuse
    re.compile(r"(\(\w*>=.*\)\(\w*<=.*\))", re.IGNORECASE),
    re.compile(r"(\(\&\(\w*>=.*\)\(\w*<=.*\)\))", re.IGNORECASE),
    
    # Active Directory specific
    re.compile(r"(\(objectCategory=person\))", re.IGNORECASE),
    re.compile(r"(\(objectSid=.*\))", re.IGNORECASE),
    re.compile(r"(\(whenCreated>=.*\))", re.IGNORECASE),
    
    # Group membership manipulation
    re.compile(r"(\(member=.*\)|\(memberOf=.*\))", re.IGNORECASE),
    re.compile(r"(\(uniqueMember=.*\))", re.IGNORECASE),
    
    # Schema discovery attempts
    re.compile(r"(\(objectClasses=\*\))", re.IGNORECASE),
    re.compile(r"(\(attributeTypes=\*\))", re.IGNORECASE),
    
    # Error-based injection indicators
    re.compile(r"(\(\w*=.*\)randomattribute)", re.IGNORECASE),
    re.compile(r"(\(\w*=.*\)\(\w*invalidattr=.*\))", re.IGNORECASE),

            ],
            'SSTI': [
          # === TEMPLATE ENGINE SYNTAX PATTERNS (Template-specific) ===
    
    # Core template delimiters
    re.compile(r"\{\{.*?\}\}", re.IGNORECASE),                  # Jinja2 / Handlebars
    re.compile(r"\{%.*?%\}", re.IGNORECASE),                    # Jinja2 block
    re.compile(r"<%.*?%>", re.IGNORECASE),                      # ERB, ASP
    re.compile(r"\[\[.*?\]\]", re.IGNORECASE),                  # Angular
    re.compile(r"<#.*?>", re.IGNORECASE),                       # Freemarker directives
    re.compile(r"<@.*?/>", re.IGNORECASE),                      # Freemarker user directives
    
    # Template-specific syntax
    re.compile(r"\(@.*?@\)", re.IGNORECASE),                    # Razor
    re.compile(r"@\{.*?\}", re.IGNORECASE),                     # Razor
    re.compile(r"@\(.*?\)", re.IGNORECASE),                     # Razor expressions
    re.compile(r"\{\{\{.*?\}\}\}", re.IGNORECASE),              # Unescaped Handlebars
    re.compile(r"\{\{&.*?\}\}", re.IGNORECASE),                 # Unescaped Handlebars alt
    re.compile(r"\{\{!.*?\}\}", re.IGNORECASE),                 # Handlebars comments
    re.compile(r"\{\{#.*?\}\}", re.IGNORECASE),                 # Handlebars helpers
    re.compile(r"\{\{/.*?\}\}", re.IGNORECASE),                 # Handlebars closing
    re.compile(r"\{\{\^.*?\}\}", re.IGNORECASE),                # Handlebars inverted
    re.compile(r"\{\{>.*?\}\}", re.IGNORECASE),                 # Handlebars partials
    
    # === PYTHON-SPECIFIC SSTI PATTERNS ===
    
    # Python object introspection
    re.compile(r"\{\{.*?\.__class__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__mro__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__subclasses__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__globals__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__init__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__doc__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__module__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__dict__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__bases__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__import__.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.__builtins__.*?\}\}", re.IGNORECASE),
    
    # Flask/Jinja2 specific objects
    re.compile(r"\{\{.*?config.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?self.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?request.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?url_for.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?get_flashed_messages.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?session.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?g\..*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?cycler.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?joiner.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?namespace.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?lipsum.*?\}\}", re.IGNORECASE),
    
    # === JINJA2 FILTER EXPLOITATION ===
    
    re.compile(r"\{\{.*?\|attr.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\|format.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\|safe.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\|list.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\|string.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\|int.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\|length.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\|reverse.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\|xmlattr.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\|urlencode.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\|.*?\|.*?\|.*?\}\}", re.IGNORECASE),   # Multiple filters
    re.compile(r"\{\{.*?\|\s*\w+\s*\(.*?\).*?\}\}", re.IGNORECASE), # Filter with args
    
    # === VELOCITY TEMPLATE SPECIFIC ===
    
    re.compile(r"#set\s*\(\s*\$\w+\s*=\s*.+?\)", re.IGNORECASE),
    re.compile(r"#if\s*\(.*?\)", re.IGNORECASE),
    re.compile(r"#foreach\s*\(.*?\)", re.IGNORECASE),
    re.compile(r"#define\s*\(\s*\$\w+\s*\)", re.IGNORECASE),
    re.compile(r"#macro\s*\(\s*\w+.*?\)", re.IGNORECASE),
    re.compile(r"#parse\s*\(.*?\)", re.IGNORECASE),
    re.compile(r"#include\s*\(.*?\)", re.IGNORECASE),
    re.compile(r"#evaluate\s*\(.*?\)", re.IGNORECASE),
    re.compile(r"\$!?\{.*?\}", re.IGNORECASE),                   # Velocity variables
    re.compile(r"\$!?\w+\..*?\(.*?\)", re.IGNORECASE),          # Velocity method calls
    
    # === FREEMARKER SPECIFIC ===
    
    re.compile(r"<#assign\s+.*?>", re.IGNORECASE),
    re.compile(r"<#if\s+.*?>", re.IGNORECASE),
    re.compile(r"<#list\s+.*?>", re.IGNORECASE),
    re.compile(r"<#include\s+.*?>", re.IGNORECASE),
    re.compile(r"<#import\s+.*?>", re.IGNORECASE),
    
    # === THYMELEAF SPECIFIC ===
    
    re.compile(r"th:.*?=", re.IGNORECASE),
    re.compile(r"\*\{.*?\}", re.IGNORECASE),                    # Selection expressions
    re.compile(r"@\{.*?\}", re.IGNORECASE),                     # Link expressions
    re.compile(r"~\{.*?\}", re.IGNORECASE),                     # Fragment expressions
    
    # === SMARTY SPECIFIC ===
    
    re.compile(r"\{\$.*?\}", re.IGNORECASE),                    # Smarty variables
    re.compile(r"\{if\s+.*?\}", re.IGNORECASE),                 # Smarty conditionals+
    re.compile(r"\{foreach\s+.*?\}", re.IGNORECASE),            # Smarty loops
    re.compile(r"\{include\s+.*?\}", re.IGNORECASE),            # Smarty includes
    re.compile(r"\{assign\s+.*?\}", re.IGNORECASE),             # Smarty assignments
    
    # === TWIG SPECIFIC ===
    
    re.compile(r"\{\{.*?dump\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?attribute\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?constant\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?_self.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?app\..*?\}\}", re.IGNORECASE),
    
    # === ASP.NET SPECIFIC ===
    
    re.compile(r"<%=.*?%>", re.IGNORECASE),                     # ASP classic
    re.compile(r"<%#.*?%>", re.IGNORECASE),                     # ASP.NET databind
    re.compile(r"<%:.*?%>", re.IGNORECASE),                     # ASP.NET encoded
    re.compile(r"<%\$.*?%>", re.IGNORECASE),                    # ASP.NET expressions
    
    # === ADVANCED TEMPLATE EXPLOITATION ===
    
    # Advanced access patterns
    re.compile(r"\{\{.*?\[.*?\[.*?\].*?\].*?\}\}", re.IGNORECASE), # Double indexing
    re.compile(r"\{\{.*?\(.*?\).*?\}\}", re.IGNORECASE),        # Function calls
    re.compile(r"\{\{.*?\.pop\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.get\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.keys\(\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.values\(\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\.items\(\).*?\}\}", re.IGNORECASE),
    
    # Template variable patterns
    re.compile(r"\{\{\s*[\w\[\]\(\)\.\_\-\'\"]+\s*\}\}", re.IGNORECASE),
    re.compile(r"\{\{\s*['\"].*?['\"]\s*\}\}", re.IGNORECASE),
    re.compile(r"\{\{\s*.*?\s*\|\s*.*?\s*\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\+.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?join.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\[\d+\].*?\}\}", re.IGNORECASE),
    
    # File operations via templates
    re.compile(r"\{\{.*?open\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?file\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?read\(.*?\).*?\}\}", re.IGNORECASE),
    
    # Environment access via templates
    re.compile(r"\{\{.*?os\.environ.*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?env\[.*?\].*?\}\}", re.IGNORECASE),
    
    # Import operations in templates
    re.compile(r"\{\{.*?__import__\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?importlib.*?\}\}", re.IGNORECASE),
    
    # Template encoding/obfuscation
    re.compile(r"\{\{.*?chr\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?ord\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?hex\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?oct\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?\[.*?:.*?\].*?\}\}", re.IGNORECASE),    # Slicing
    re.compile(r"\{\{.*?range\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?enumerate\(.*?\).*?\}\}", re.IGNORECASE),
    re.compile(r"\{\{.*?zip\(.*?\).*?\}\}", re.IGNORECASE),
    # Template comments for bypass
    re.compile(r"\{#.*?#\}", re.IGNORECASE),                    # Jinja2 comments
    re.compile(r"\{%\s*comment\s*%\}.*?\{%\s*endcomment\s*%\}", re.IGNORECASE | re.DOTALL),
    
    # Mathematical operations in templates
    re.compile(r"\{\{.*?\*\*.*?\}\}", re.IGNORECASE),          # Power operations
    re.compile(r"\{\{.*?//.*?\}\}", re.IGNORECASE),            # Floor division

            ],
            
            'XXE': [
             # XML External Entity (XXE) attack patterns
        re.compile(r"<!ENTITY\s+\w+\s+SYSTEM\s+['\"](?:file|ftp|http|https):\/\/[^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"<!ENTITY\s+\w+\s+PUBLIC\s+['\"][^'\"]+['\"]\s+['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"<!DOCTYPE\s+\w+\s+\[", re.IGNORECASE),
        re.compile(r"<!DOCTYPE[^>]+SYSTEM\s+['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"<!DOCTYPE[^>]+PUBLIC\s+['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"<!ENTITY\s+\w+\s+['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"<!\[CDATA\[.*?&\w+;.*?\]\]>", re.IGNORECASE | re.DOTALL),
                
        # 1. Parameter Entity Injection
        re.compile(r"<!ENTITY\s+%\s*\w+\s+SYSTEM\s+['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"<!ENTITY\s+%\s*\w+\s+PUBLIC\s+['\"][^'\"]+['\"]\s+['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"<!ENTITY\s+%\s*\w+\s+['\"][^'\"]*%[^'\"]*['\"]", re.IGNORECASE),
        re.compile(r"%\w+;", re.IGNORECASE),  # Parameter entity reference
        
        # 2. Nested Entity Definitions
        re.compile(r"<!ENTITY\s+\w+\s+['\"][^'\"]*<!ENTITY[^'\"]*['\"]", re.IGNORECASE),
        re.compile(r"<!ENTITY\s+\w+\s+['\"][^'\"]*&\w+;[^'\"]*['\"]", re.IGNORECASE),
        
        # 3. External DTD References
        re.compile(r"<!DOCTYPE\s+\w+\s+SYSTEM\s+['\"](?:file|ftp|http|https|data):[^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"<!DOCTYPE\s+\w+\s+PUBLIC\s+['\"][^'\"]+['\"]\s+['\"](?:file|ftp|http|https|data):[^'\"]+['\"]", re.IGNORECASE),
        
        # 4. Protocol-specific XXE attempts
        re.compile(r"<!ENTITY[^>]+file:\/\/[^>]+>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+ftp:\/\/[^>]+>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+http:\/\/[^>]+>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+https:\/\/[^>]+>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+data:[^>]+>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+jar:file:[^>]+>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+netdoc:[^>]+>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+gopher:[^>]+>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+expect:[^>]+>", re.IGNORECASE),
        
        # 5. Common file paths in XXE
        re.compile(r"<!ENTITY[^>]+file:\/\/\/etc\/passwd[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+file:\/\/\/etc\/shadow[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+file:\/\/\/etc\/hosts[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+file:\/\/\/proc\/version[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+file:\/\/\/proc\/self\/environ[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+file:\/\/\/proc\/self\/cmdline[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+file:\/\/\/windows\/system32\/drivers\/etc\/hosts[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+file:\/\/\/c:\/windows\/system32\/drivers\/etc\/hosts[^>]*>", re.IGNORECASE),
        
        # 6. Blind XXE with Out-of-Band (OOB) techniques
        re.compile(r"<!ENTITY[^>]+http:\/\/[^\/]*\.burpcollaborator\.net[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+http:\/\/[^\/]*\.ngrok\.io[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+http:\/\/[^\/]*\.requestcatcher\.com[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+http:\/\/[^\/]*\.webhook\.site[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+ftp:\/\/[^\/]*\.attacker\.[^>]*>", re.IGNORECASE),
        
        # 7. Entity recursion/billion laughs patterns
        re.compile(r"<!ENTITY\s+\w+\s+['\"][^'\"]*&\w+;&\w+;[^'\"]*['\"]", re.IGNORECASE),
        re.compile(r"<!ENTITY\s+\w+\s+['\"][^'\"]*(&\w+;){2,}[^'\"]*['\"]", re.IGNORECASE),
        
        # 8. XML Inclusion (XInclude) attacks
        re.compile(r"<xi:include[^>]+href\s*=\s*['\"]file:[^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"<xi:include[^>]+href\s*=\s*['\"]http[s]?:[^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"<xi:include[^>]+href\s*=\s*['\"]ftp:[^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"xmlns:xi\s*=\s*['\"]http:\/\/www\.w3\.org\/2001\/XInclude['\"]", re.IGNORECASE),
        
        # 9. SOAP/XML-RPC specific XXE patterns
        re.compile(r"<soap:Envelope[^>]*>.*<!ENTITY.*</soap:Envelope>", re.IGNORECASE | re.DOTALL),
        re.compile(r"<methodCall[^>]*>.*<!ENTITY.*</methodCall>", re.IGNORECASE | re.DOTALL),
        
        # 10. Base64 encoded XXE payloads
        re.compile(r"<!ENTITY[^>]+data:text\/plain;base64,[A-Za-z0-9+/=]+[^>]*>", re.IGNORECASE),
        
        # 11. UTF-16/UTF-32 encoding bypass attempts
        re.compile(r"<!ENTITY[^>]+&#x[0-9a-f]+;[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+&#[0-9]+;[^>]*>", re.IGNORECASE),
        
        # 12. PHP wrapper exploitation
        re.compile(r"<!ENTITY[^>]+php:\/\/filter[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+php:\/\/input[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+compress\.zlib:\/\/[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+compress\.bzip2:\/\/[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+zip:\/\/[^>]*>", re.IGNORECASE),
        
        # 13. Java-specific protocol handlers
        re.compile(r"<!ENTITY[^>]+jar:file:[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+netdoc:[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+mailto:[^>]*>", re.IGNORECASE),
        
        # 14. Error-based XXE detection
        re.compile(r"<!ENTITY[^>]+file:\/\/\/nonexistent[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+file:\/\/\/dev\/random[^>]*>", re.IGNORECASE),
        
        # 15. Advanced DTD syntax variations
        re.compile(r"<!ENTITY\s+\w+\s+SYSTEM\s+['\"][^'\"]+['\"]\s+NDATA\s+\w+", re.IGNORECASE),
        re.compile(r"<!NOTATION\s+\w+\s+SYSTEM\s+['\"][^'\"]+['\"]", re.IGNORECASE),
        
        # 16. Internal subset with external references
        re.compile(r"<!DOCTYPE\s+\w+\s+\[[^\]]*<!ENTITY[^\]]*SYSTEM[^\]]*\]>", re.IGNORECASE | re.DOTALL),
        re.compile(r"<!DOCTYPE\s+\w+\s+\[[^\]]*%[^\]]*;[^\]]*\]>", re.IGNORECASE | re.DOTALL),
        
        # 17. Conditional sections in DTD
        re.compile(r"<!\[INCLUDE\[[^\]]*<!ENTITY[^\]]*\]\]>", re.IGNORECASE | re.DOTALL),
        re.compile(r"<!\[IGNORE\[[^\]]*<!ENTITY[^\]]*\]\]>", re.IGNORECASE | re.DOTALL),
        
        # 18. Attribute list declarations with external entities
        re.compile(r"<!ATTLIST[^>]+ENTITY[^>]+>", re.IGNORECASE),
        re.compile(r"<!ATTLIST[^>]+ENTITIES[^>]+>", re.IGNORECASE),
        
        # 19. Complex nested parameter entities
        re.compile(r"%\w+;\s*<!ENTITY", re.IGNORECASE),
        re.compile(r"<!ENTITY\s+%\w+[^>]*%\w+;[^>]*>", re.IGNORECASE),
        
        # 20. SVG-based XXE (since SVG can contain XML)
        re.compile(r"<svg[^>]*>.*<!ENTITY.*</svg>", re.IGNORECASE | re.DOTALL),
        re.compile(r"<svg[^>]*>.*<!DOCTYPE.*</svg>", re.IGNORECASE | re.DOTALL),
        
        # 21. XSLT-based XXE
        re.compile(r"<xsl:stylesheet[^>]*>.*<!ENTITY.*</xsl:stylesheet>", re.IGNORECASE | re.DOTALL),
        re.compile(r"document\s*\(\s*['\"]file:[^'\"]+['\"]", re.IGNORECASE),
        
        # 22. XML Schema-based attacks
        re.compile(r"<xs:schema[^>]*>.*<!ENTITY.*</xs:schema>", re.IGNORECASE | re.DOTALL),
        re.compile(r"schemaLocation\s*=\s*['\"]file:[^'\"]+['\"]", re.IGNORECASE),
        
        # 23. Office document XXE (DOCX, XLSX, etc.)
        re.compile(r"application\/vnd\.openxmlformats[^>]*<!ENTITY", re.IGNORECASE),
        re.compile(r"\.xml[^>]*<!ENTITY[^>]*SYSTEM", re.IGNORECASE),
        
        # 24. Entity reference variations
        re.compile(r"&[a-zA-Z_][\w.-]*;", re.IGNORECASE),  # General entity references
        re.compile(r"&#x[0-9a-fA-F]+;", re.IGNORECASE),    # Hexadecimal character references
        re.compile(r"&#[0-9]+;", re.IGNORECASE),            # Decimal character references
        
        # 25. Time-based XXE detection
        re.compile(r"<!ENTITY[^>]+\/dev\/random[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+\/dev\/urandom[^>]*>", re.IGNORECASE),
        
        # 26. Windows-specific paths
        re.compile(r"<!ENTITY[^>]+file:\/\/\/c:\/[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+file:\/\/\/d:\/[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+\\\\[^>]*>", re.IGNORECASE),  # UNC paths
        
        # 27. Cloud metadata service exploitation
        re.compile(r"<!ENTITY[^>]+http:\/\/169\.254\.169\.254[^>]*>", re.IGNORECASE),  # AWS
        re.compile(r"<!ENTITY[^>]+http:\/\/metadata\.google\.internal[^>]*>", re.IGNORECASE),  # GCP
        re.compile(r"<!ENTITY[^>]+http:\/\/169\.254\.169\.254\/metadata[^>]*>", re.IGNORECASE),  # Azure
        
        # 28. Protocol smuggling attempts
        re.compile(r"<!ENTITY[^>]+file:\/file:[^>]*>", re.IGNORECASE),
        re.compile(r"<!ENTITY[^>]+http:\/file:[^>]*>", re.IGNORECASE),
        
        # 29. Bypass attempts with different encodings
        re.compile(r"<!ENTITY[^>]+%[0-9a-fA-F]{2}[^>]*>", re.IGNORECASE),  # URL encoding
        re.compile(r"<!ENTITY[^>]+\\u[0-9a-fA-F]{4}[^>]*>", re.IGNORECASE),  # Unicode escape
        
        # 30. Advanced parameter entity recursion
        re.compile(r"<!ENTITY\s+%\s*\w+\s+['\"][^'\"]*%\s*\w+;[^'\"]*['\"]", re.IGNORECASE),
        re.compile(r"<!ENTITY\s+%\s*\w+\s+SYSTEM\s+['\"][^'\"]*\?%\s*\w+;[^'\"]*['\"]", re.IGNORECASE),
    
            ],
            
            'HEADER_INJECTION': [
            # HTTP Header Injection patterns
        re.compile(r"(\r\n|\r|\n)", re.IGNORECASE),
        re.compile(r"(%0d%0a|%0d|%0a)", re.IGNORECASE),
        re.compile(r"(%0D%0A|%0D|%0A)", re.IGNORECASE),
        re.compile(r"(\\u000d\\u000a|\\u000d|\\u000a)", re.IGNORECASE),
        re.compile(r"(Content-Length\s*:)", re.IGNORECASE),
        re.compile(r"(Set-Cookie\s*:)", re.IGNORECASE),
        re.compile(r"(Location\s*:)", re.IGNORECASE),
        re.compile(r"(Refresh\s*:)", re.IGNORECASE),
        re.compile(r"(X-Forwarded-.*?:)", re.IGNORECASE),
        re.compile(r"(\x0d|\x0a|\x0d\x0a)", re.IGNORECASE),
        re.compile(r"(\\x0d|\\x0a|\\x0d\\x0a)", re.IGNORECASE),
        re.compile(r"(Injected-Header\s*:)", re.IGNORECASE),
        re.compile(r"(X-[\w-]*Injected\s*:)", re.IGNORECASE),
    
    # Eksik olan önemli pattern'ler
   
    # Alternative encoding patterns
    re.compile(r"(\\\r|\\\n|\\\r\\\n)", re.IGNORECASE),
    re.compile(r"(\\013|\\012|\\015)", re.IGNORECASE),  # Octal encoding
    re.compile(r"(\x0B|\x0C|\x1C|\x1D|\x1E|\x1F)", re.IGNORECASE),  # Other control chars
    
    # Space and tab variations
    re.compile(r"(\t|\v|\f)", re.IGNORECASE),  # Tab, vertical tab, form feed
    re.compile(r"(%09|%0B|%0C)", re.IGNORECASE),  # URL encoded whitespace chars
    
    
    # PHP specific headers
    re.compile(r"(X-PHP-.*?:)", re.IGNORECASE),
    
    # Server specific headers
    re.compile(r"(Server\s*:)", re.IGNORECASE),
    re.compile(r"(X-Powered-By\s*:)", re.IGNORECASE),
    re.compile(r"(X-AspNet-Version\s*:)", re.IGNORECASE),
    re.compile(r"(X-AspNetMvc-Version\s*:)", re.IGNORECASE),
            ],
        }

    def get_additional_ip_services(self, ip_address):
        """Ek IP servisleri - daha fazla bilgi almak için"""
        additional_info = {}
        
        try:
            # IP-API.com'dan detailed query
            ipapi_url = f"http://ip-api.com/json/{ip_address}?fields=66846719"  # All fields
            response = requests.get(ipapi_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    additional_info['ipapi_detailed'] = data
        except:
            pass
        
        try:
            # IPInfo.io - ücretsiz token gerekmiyor
            ipinfo_url = f"http://ipinfo.io/{ip_address}/json"
            response = requests.get(ipinfo_url, timeout=5)
            if response.status_code == 200:
                additional_info['ipinfo'] = response.json()
        except:
            pass
        
        try:
            # GeoJS - ücretsiz servis
            geojs_url = f"https://get.geojs.io/v1/ip/geo/{ip_address}.json"
            response = requests.get(geojs_url, timeout=5)
            if response.status_code == 200:
                additional_info['geojs'] = response.json()
        except:
            pass
        
        return additional_info

    def get_ip_reputation_check(self, ip_address):
        """IP reputation kontrolü - kötü amaçlı IP tespiti"""
        reputation_info = {
            'is_malicious': False,
            'threat_types': [],
            'risk_score': 0,
            'sources': []
        }
        
        try:
            # AbuseIPDB benzeri ücretsiz kontroller
            # Burada gerçek API yerine basic kontroller yapıyoruz
            
            # Tor exit node kontrolü
            if self.is_tor_exit_node(ip_address):
                reputation_info['threat_types'].append('Tor Exit Node')
                reputation_info['risk_score'] += 30
                reputation_info['sources'].append('Tor Network Check')
            
            # VPN/Proxy kontrolü (basit)
            if self.is_likely_vpn_proxy(ip_address):
                reputation_info['threat_types'].append('Possible VPN/Proxy')
                reputation_info['risk_score'] += 20
                reputation_info['sources'].append('VPN/Proxy Detection')
            
            # Risk skoruna göre kötü amaçlı belirleme
            reputation_info['is_malicious'] = reputation_info['risk_score'] >= 50
            
        except Exception as e:
            logger.warning(f"IP reputation check hatası: {str(e)}")
        
        return reputation_info

    def is_tor_exit_node(self, ip_address):
        """Tor exit node kontrolü - basit kontrol"""
        try:
            # Tor Project'in exit node listesi kontrolü (bu gerçek bir örnek değil)
            # Gerçek uygulamada Tor exit node listesi kontrol edilir
            return False  # Placeholder
        except:
            return False

    def is_likely_vpn_proxy(self, ip_address):
        """VPN/Proxy olasılığı kontrolü"""
        try:
            # ASN ve ISP isimlerinden VPN/Proxy tespiti
            # Bu bilgi IP geolocation'dan gelir
            return False  # Placeholder - gerçek implementasyon gerekli
        except:
            return False

    def get_ip_geolocation(self, ip_address):
        """IP adresinin coğrafi konumunu ve detaylı bilgilerini al - Geliştirilmiş versiyon"""
        if not self.ip_api_enabled or not ip_address or ip_address == 'Bilinmiyor':
            return None
        
        # Özel IP aralıklarını kontrol et (local, private IPs)
        private_ips = ['127.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                      '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', 
                      '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', 
                      '172.30.', '172.31.', '192.168.']
        
        if any(ip_address.startswith(private) for private in private_ips):
            return {
                'status': 'fail',
                'message': 'Özel IP adresi (local/private network)',
                'query': ip_address
            }
        
        # Cache kontrolü - aynı IP için 30 dakika cache
        cache_key = f"ip_geolocation_detailed:{ip_address}"
        cached_result = cache.get(cache_key)
        if cached_result:
            return cached_result
        
        try:
            # IP-API.com'dan tüm mevcut alanları iste - extended version
            # Tüm mevcut alanları almak için özel fields kodu
            fields = "status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,mobile,proxy,hosting,query"
            
            url = f"http://ip-api.com/json/{ip_address}?fields={fields}&lang=tr"
            
            response = requests.get(url, timeout=self.ip_api_timeout)
            response.raise_for_status()
            
            geo_data = response.json()
            
            # Ek servislerde bilgi al
            additional_services = self.get_additional_ip_services(ip_address)
            geo_data['additional_services'] = additional_services
            
            # IP reputation kontrolü
            reputation = self.get_ip_reputation_check(ip_address)
            geo_data['reputation'] = reputation
            
            # DNS reverse lookup
            try:
                reverse_dns = socket.gethostbyaddr(ip_address)[0]
                geo_data['reverse_dns'] = reverse_dns
            except:
                geo_data['reverse_dns'] = 'Bulunamadı'
            
            # WHOIS benzeri bilgiler (basit)
            geo_data['whois_info'] = self.get_basic_whois_info(ip_address)
            
            # Port scan detection bilgileri
            geo_data['security_analysis'] = self.analyze_ip_security(ip_address)
            
            # Başarılı response'u cache'le (30 dakika)
            if geo_data.get('status') == 'success':
                cache.set(cache_key, geo_data, 1800)
            
            return geo_data
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"IP geolocation API hatası: {str(e)}")
            return {
                'status': 'fail',
                'message': f'API bağlantı hatası: {str(e)}',
                'query': ip_address
            }
        except Exception as e:
            logger.error(f"IP geolocation genel hatası: {str(e)}")
            return {
                'status': 'fail',
                'message': f'Genel hata: {str(e)}',
                'query': ip_address
            }

    def get_basic_whois_info(self, ip_address):
        """Basit WHOIS bilgisi"""
        try:
            # Bu gerçek bir WHOIS implementasyonu değil, örnek
            return {
                'registrar': 'Bilinmiyor',
                'creation_date': 'Bilinmiyor',
                'expiration_date': 'Bilinmiyor',
                'nameservers': 'Bilinmiyor'
            }
        except:
            return {'error': 'WHOIS bilgisi alınamadı'}

    def analyze_ip_security(self, ip_address):
        """IP güvenlik analizi"""
        analysis = {
            'suspicious_patterns': [],
            'threat_level': 'LOW',
            'recommendations': []
        }
        
        try:
            # Basit güvenlik analizi
            # Gerçek uygulamada daha detaylı kontroller yapılır
            
            analysis['recommendations'].append('IP adresini blacklist kontrolü yapın')
            analysis['recommendations'].append('Bu IP\'den gelen istekleri izleyin')
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    def get_extended_client_info(self, request):
        """Genişletilmiş istemci bilgileri toplama"""
        # Temel bilgileri al
        basic_info = self.get_client_info(request)
        
        # Ek HTTP header'ları analiz et
        extended_headers = {}
        security_headers = [
            'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED_PROTO',
            'HTTP_X_FORWARDED_HOST', 'HTTP_X_ORIGINAL_HOST', 'HTTP_CF_CONNECTING_IP',
            'HTTP_CF_IPCOUNTRY', 'HTTP_CF_RAY', 'HTTP_CF_VISITOR',
            'HTTP_X_REQUESTED_WITH', 'HTTP_X_HTTP_METHOD_OVERRIDE',
            'HTTP_ACCEPT_LANGUAGE', 'HTTP_ACCEPT_ENCODING', 'HTTP_ACCEPT_CHARSET',
            'HTTP_AUTHORIZATION', 'HTTP_COOKIE', 'HTTP_REFERER',
            'HTTP_ORIGIN', 'HTTP_DNT', 'HTTP_UPGRADE_INSECURE_REQUESTS',
            'HTTP_SEC_FETCH_SITE', 'HTTP_SEC_FETCH_MODE', 'HTTP_SEC_FETCH_DEST',
            'HTTP_SEC_FETCH_USER', 'HTTP_CACHE_CONTROL', 'HTTP_PRAGMA'
        ]
        
        for header in security_headers:
            if header in request.META:
                extended_headers[header] = request.META[header]
        
        # Browser fingerprinting
        browser_info = self.analyze_user_agent(basic_info.get('user_agent', ''))
        
        # Request timing
        request_timing = {
            'request_time': datetime.now().isoformat(),
            'server_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z'),
            'timezone': 'UTC+3'  # Türkiye saati
        }
        
        # Session bilgileri
        session_info = {}
        if hasattr(request, 'session'):
            session_info = {
                'session_key': getattr(request.session, 'session_key', 'Yok'),
                'session_data_keys': list(request.session.keys()) if request.session else []
            }
        
        # Genişletilmiş bilgileri birleştir
        extended_info = {
            **basic_info,
            'extended_headers': extended_headers,
            'browser_analysis': browser_info,
            'request_timing': request_timing,
            'session_info': session_info,
            'request_size': self.calculate_request_size(request),
            'is_ajax': request.headers.get('X-Requested-With') == 'XMLHttpRequest',
            'connection_info': self.get_connection_info(request)
        }
        
        return extended_info

    def analyze_user_agent(self, user_agent):
        """User Agent analizi - browser fingerprinting"""
        analysis = {
            'browser': 'Bilinmiyor',
            'version': 'Bilinmiyor',
            'os': 'Bilinmiyor',
            'device': 'Bilinmiyor',
            'is_bot': False,
            'is_mobile': False,
            'suspicious_patterns': []
        }
        
        if not user_agent:
            return analysis
        
        user_agent_lower = user_agent.lower()
        
        # Browser detection
        if 'chrome' in user_agent_lower:
            analysis['browser'] = 'Chrome'
        elif 'firefox' in user_agent_lower:
            analysis['browser'] = 'Firefox'
        elif 'safari' in user_agent_lower and 'chrome' not in user_agent_lower:
            analysis['browser'] = 'Safari'
        elif 'edge' in user_agent_lower:
            analysis['browser'] = 'Edge'
        elif 'opera' in user_agent_lower:
            analysis['browser'] = 'Opera'
        
        # OS detection
        if 'windows' in user_agent_lower:
            analysis['os'] = 'Windows'
        elif 'mac' in user_agent_lower or 'macos' in user_agent_lower:
            analysis['os'] = 'macOS'
        elif 'linux' in user_agent_lower:
            analysis['os'] = 'Linux'
        elif 'android' in user_agent_lower:
            analysis['os'] = 'Android'
        elif 'ios' in user_agent_lower or 'iphone' in user_agent_lower:
            analysis['os'] = 'iOS'
        
        # Mobile detection
        mobile_indicators = ['mobile', 'android', 'iphone', 'ipad', 'tablet']
        analysis['is_mobile'] = any(indicator in user_agent_lower for indicator in mobile_indicators)
        
        # Bot detection
        bot_indicators = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'python', 
            'java', 'go-http', 'postman', 'insomnia', 'httpclient'
        ]
        analysis['is_bot'] = any(bot in user_agent_lower for bot in bot_indicators)
        
        # Suspicious patterns
        suspicious_patterns = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'zap', 'burp', 'metasploit',
            'havij', 'acunetix', 'nessus', 'openvas', 'w3af', 'skipfish'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in user_agent_lower:
                analysis['suspicious_patterns'].append(pattern)
        
        return analysis

    def calculate_request_size(self, request):
        """İstek boyutunu hesapla"""
        try:
            size = 0
            
            # Headers boyutu
            for key, value in request.META.items():
                if key.startswith('HTTP_'):
                    size += len(str(key)) + len(str(value))
            
            # GET parametreleri
            if hasattr(request, 'GET'):
                for key, value in request.GET.items():
                    size += len(str(key)) + len(str(value))
            
            # POST data
            if hasattr(request, 'POST'):
                for key, value in request.POST.items():
                    size += len(str(key)) + len(str(value))
            
            # Body boyutu
            if hasattr(request, 'body'):
                size += len(request.body)
            
            return {
                'total_bytes': size,
                'size_category': 'Normal' if size < 8192 else 'Büyük' if size < 65536 else 'Çok Büyük'
            }
        except:
            return {'total_bytes': 0, 'size_category': 'Bilinmiyor'}

    def get_connection_info(self, request):
        """Bağlantı bilgilerini topla"""
        connection_info = {
            'protocol': request.META.get('SERVER_PROTOCOL', 'Bilinmiyor'),
            'method': request.method,
            'is_secure': request.is_secure(),
            'port': request.META.get('SERVER_PORT', 'Bilinmiyor'),
            'content_type': request.META.get('CONTENT_TYPE', 'Bilinmiyor'),
            'content_length': request.META.get('CONTENT_LENGTH', 'Bilinmiyor'),
            'query_string': request.META.get('QUERY_STRING', ''),
            'path_info': request.META.get('PATH_INFO', ''),
            'remote_addr': request.META.get('REMOTE_ADDR', 'Bilinmiyor'),
            'server_name': request.META.get('SERVER_NAME', 'Bilinmiyor')
        }
        
        return connection_info

    def get_client_info(self, request):
        """İstemci bilgilerini topla - Temel versiyon"""
        # IP adresi
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', 'Bilinmiyor')
        
        # User Agent
        user_agent = request.META.get('HTTP_USER_AGENT', 'Bilinmiyor')
        
        # Hostname (güvenli bir şekilde)
        hostname = 'Bilinmiyor'
        try:
            if ip and ip != 'Bilinmiyor':
                hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            pass
        
        # IP Geolocation bilgilerini al
        geo_info = self.get_ip_geolocation(ip)
        
        # İstek bilgileri
        request_info = {
            'ip': ip,
            'hostname': hostname,
            'user_agent': user_agent,
            'method': request.method,
            'path': request.path,
            'get_params': dict(request.GET) if hasattr(request, 'GET') and request.GET else {},
            'post_params': dict(request.POST) if hasattr(request, 'POST') and request.POST else {},
            'headers': {k: v for k, v in request.META.items() if k.startswith('HTTP_')},
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'geolocation': geo_info
        }
        
        return request_info
    
    def detect_attack_type(self, request_data):
        """Saldırı türünü tespit et"""
        # Tüm veriyi birleştir
        all_data_parts = [
            str(request_data.get('get_params', '')),
            str(request_data.get('post_params', '')),
            str(request_data.get('headers', '')),
            request_data.get('path', ''),
            request_data.get('user_agent', '')
        ]
        all_data = ' '.join(all_data_parts).lower()
        
        # Her saldırı türü için kontrol et
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if pattern.search(all_data):
                    return attack_type
        
        return 'UNKNOWN'
    
    def format_enhanced_geolocation_info(self, geo_info):
        """Geliştirilmiş geolocation bilgilerini HTML formatında düzenle"""
        if not geo_info or geo_info.get('status') != 'success':
            return f"""
            <div class="geo-info-error">
                <h4>🌍 Coğrafi Konum Bilgisi</h4>
                <p>❌ Konum bilgisi alınamadı: {geo_info.get('message', 'Bilinmeyen hata') if geo_info else 'IP geolocation devre dışı'}</p>
            </div>
            """
        
        # Bayrak emoji'lerini ülke koduna göre belirle
        country_flags = {
            'TR': '🇹🇷', 'US': '🇺🇸', 'GB': '🇬🇧', 'DE': '🇩🇪', 'FR': '🇫🇷', 
            'RU': '🇷🇺', 'CN': '🇨🇳', 'JP': '🇯🇵', 'IN': '🇮🇳', 'BR': '🇧🇷',
            'CA': '🇨🇦', 'AU': '🇦🇺', 'IT': '🇮🇹', 'ES': '🇪🇸', 'NL': '🇳🇱',
            'KR': '🇰🇷', 'SE': '🇸🇪', 'NO': '🇳🇴', 'DK': '🇩🇰', 'FI': '🇫🇮'
        }
        
        country_code = geo_info.get('countryCode', '')
        flag = country_flags.get(country_code, '🌍')
        
        # Proxy/Hosting durumu kontrolü
        proxy_status = "❌ Evet" if geo_info.get('proxy', False) else "✅ Hayır"
        mobile_status = "📱 Evet" if geo_info.get('mobile', False) else "💻 Hayır"
        hosting_status = "☁️ Evet" if geo_info.get('hosting', False) else "🏠 Hayır"
        
        # Reputation bilgileri
        reputation = geo_info.get('reputation', {})
        threat_level = reputation.get('threat_level', 'LOW')
        threat_color = {'LOW': 'green', 'MEDIUM': 'orange', 'HIGH': 'red'}.get(threat_level, 'gray')
        
        # Ek servislerden bilgiler
        additional_services = geo_info.get('additional_services', {})
        
        # DNS bilgileri
        reverse_dns = geo_info.get('reverse_dns', 'Bulunamadı')
        
        # Güvenlik analizi
        security_analysis = geo_info.get('security_analysis', {})
        recommendations = security_analysis.get('recommendations', [])
        
        return f"""
        <div class="geolocation-section">
            <h4>🌍 Detaylı Coğrafi Konum ve Güvenlik Analizi</h4>
            
            <div class="geo-grid">
                <div class="geo-card location-info">
                    <h5>{flag} Konum Bilgileri</h5>
                    <p><strong>🌍 Kıta:</strong> {geo_info.get('continent', 'Bilinmiyor')} ({geo_info.get('continentCode', 'N/A')})</p>
                    <p><strong>🏳️ Ülke:</strong> {geo_info.get('country', 'Bilinmiyor')} ({country_code})</p>
                    <p><strong>🏙️ Bölge:</strong> {geo_info.get('regionName', 'Bilinmiyor')} ({geo_info.get('region', 'N/A')})</p>
                    <p><strong>🏘️ Şehir:</strong> {geo_info.get('city', 'Bilinmiyor')}</p>
                    <p><strong>📍 İlçe/Bölge:</strong> {geo_info.get('district', 'Bilinmiyor')}</p>
                    <p><strong>📮 Posta Kodu:</strong> {geo_info.get('zip', 'Bilinmiyor')}</p>
                    <p><strong>🗺️ Koordinatlar:</strong> {geo_info.get('lat', 'N/A')}, {geo_info.get('lon', 'N/A')}</p>
                </div>
                
                <div class="geo-card isp-info">
                    <h5>🌐 İnternet Servis Bilgileri</h5>
                    <p><strong>📡 ISP:</strong> {geo_info.get('isp', 'Bilinmiyor')}</p>
                    <p><strong>🏢 Organizasyon:</strong> {geo_info.get('org', 'Bilinmiyor')}</p>
                    <p><strong>🔢 AS Numarası:</strong> {geo_info.get('as', 'Bilinmiyor')}</p>
                    <p><strong>📋 AS Adı:</strong> {geo_info.get('asname', 'Bilinmiyor')}</p>
                    <p><strong>🔄 Reverse DNS:</strong> {reverse_dns}</p>
                    <p><strong>⏰ Saat Dilimi:</strong> {geo_info.get('timezone', 'Bilinmiyor')}</p>
                </div>
                
                <div class="geo-card security-info">
                    <h5>🔒 Güvenlik Durumu</h5>
                    <p><strong>🕵️ Proxy Kullanımı:</strong> {proxy_status}</p>
                    <p><strong>📱 Mobil Bağlantı:</strong> {mobile_status}</p>
                    <p><strong>☁️ Hosting Servisi:</strong> {hosting_status}</p>
                    <p><strong>⚠️ Tehdit Seviyesi:</strong> <span style="color: {threat_color}; font-weight: bold;">{threat_level}</span></p>
                    <p><strong>🎯 Risk Skoru:</strong> {reputation.get('risk_score', 0)}/100</p>
                    <p><strong>🔍 Sorgu IP:</strong> {geo_info.get('query', 'Bilinmiyor')}</p>
                </div>
                
                <div class="geo-card threat-analysis">
                    <h5>🛡️ Tehdit Analizi</h5>
                    <p><strong>🚨 Tespit Edilen Tehditler:</strong></p>
                    <ul>
                        {chr(10).join([f'<li>• {threat}</li>' for threat in reputation.get('threat_types', ['Tehdit tespit edilmedi'])]) if reputation.get('threat_types') else '<li>• Tehdit tespit edilmedi</li>'}
                    </ul>
                    <p><strong>📊 Analiz Kaynakları:</strong></p>
                    <ul>
                        {chr(10).join([f'<li>• {source}</li>' for source in reputation.get('sources', ['Temel analiz'])]) if reputation.get('sources') else '<li>• Temel analiz</li>'}
                    </ul>
                </div>
            </div>
            
            {'<div class="security-recommendations">' if recommendations else ''}
                {'<h5>💡 Güvenlik Önerileri</h5>' if recommendations else ''}
                {'<ul>' if recommendations else ''}
                    {chr(10).join([f'<li>• {rec}</li>' for rec in recommendations]) if recommendations else ''}
                {'</ul>' if recommendations else ''}
            {'</div>' if recommendations else ''}
            
            {self.format_additional_services_info(additional_services) if additional_services else ''}
        </div>
        """

    def format_additional_services_info(self, additional_services):
        """Ek servislerden gelen bilgileri formatla"""
        if not additional_services:
            return ""
        
        services_html = '<div class="additional-services"><h5>🔍 Ek Servis Bilgileri</h5>'
        
        # IPInfo.io bilgileri
        if 'ipinfo' in additional_services:
            ipinfo = additional_services['ipinfo']
            services_html += f"""
            <div class="service-info">
                <strong>📍 IPInfo.io:</strong>
                Şehir: {ipinfo.get('city', 'N/A')}, 
                Bölge: {ipinfo.get('region', 'N/A')}, 
                Ülke: {ipinfo.get('country', 'N/A')}, 
                Posta: {ipinfo.get('postal', 'N/A')}
            </div>
            """
        
        # GeoJS bilgileri
        if 'geojs' in additional_services:
            geojs = additional_services['geojs']
            services_html += f"""
            <div class="service-info">
                <strong>🌐 GeoJS:</strong>
                IP: {geojs.get('ip', 'N/A')}, 
                Ülke: {geojs.get('country', 'N/A')}, 
                Accuracy: {geojs.get('accuracy', 'N/A')} km
            </div>
            """
        
        services_html += '</div>'
        return services_html

    def create_enhanced_email_content(self, attack_type, request_info, additional_info=None):
        """Geliştirilmiş e-posta içeriği oluştur"""
        attack_info = self.attack_types.get(attack_type, self.attack_types['UNKNOWN'])
        
        # Güvenli JSON serialization
        def safe_json_dumps(obj):
            try:
                return json.dumps(obj, indent=2, ensure_ascii=False)
            except (TypeError, ValueError):
                return str(obj)
        
        # Geolocation bilgilerini formatla - geliştirilmiş versiyon
        geo_section = self.format_enhanced_geolocation_info(request_info.get('geolocation'))
        
        # Browser analizi
        browser_analysis = request_info.get('browser_analysis', {})
        browser_info = f"""
        <div class="browser-analysis">
            <h4>🖥️ Browser ve Cihaz Analizi</h4>
            <div class="info-grid">
                <div class="info-card">
                    <strong>🌐 Browser:</strong> {browser_analysis.get('browser', 'Bilinmiyor')} {browser_analysis.get('version', '')}<br>
                    <strong>💻 İşletim Sistemi:</strong> {browser_analysis.get('os', 'Bilinmiyor')}<br>
                    <strong>📱 Cihaz Türü:</strong> {'Mobil' if browser_analysis.get('is_mobile') else 'Masaüstü'}<br>
                    <strong>🤖 Bot Olasılığı:</strong> {'Evet' if browser_analysis.get('is_bot') else 'Hayır'}
                </div>
                <div class="info-card">
                    <strong>⚠️ Şüpheli Pattern'ler:</strong><br>
                    {', '.join(browser_analysis.get('suspicious_patterns', ['Yok'])) if browser_analysis.get('suspicious_patterns') else 'Tespit edilmedi'}
                </div>
            </div>
        </div>
        """
        
        # Extended headers bilgisi
        extended_headers = request_info.get('extended_headers', {})
        headers_info = ""
        if extended_headers:
            headers_info = f"""
            <h3>🔍 Gelişmiş Header Analizi</h3>
            <div class="code">
                {safe_json_dumps(extended_headers)}
            </div>
            """
        
        # Request size analizi
        request_size = request_info.get('request_size', {})
        size_info = f"""
        <div class="request-analysis">
            <h4>📊 İstek Analizi</h4>
            <p><strong>📏 İstek Boyutu:</strong> {request_size.get('total_bytes', 0)} bytes ({request_size.get('size_category', 'Bilinmiyor')})</p>
            <p><strong>🔗 AJAX İstek:</strong> {'Evet' if request_info.get('is_ajax') else 'Hayır'}</p>
            <p><strong>🕒 İstek Zamanlaması:</strong> {request_info.get('request_timing', {}).get('request_time', 'Bilinmiyor')}</p>
        </div>
        """
        
        # Session bilgileri
        session_info = request_info.get('session_info', {})
        session_section = ""
        if session_info:
            session_section = f"""
            <h3>👤 Session Bilgileri</h3>
            <div class="code">
                <strong>Session Key:</strong> {session_info.get('session_key', 'Yok')}<br>
                <strong>Session Data Keys:</strong> {', '.join(session_info.get('session_data_keys', []))}
            </div>
            """
        
        # HTML e-posta şablonu - Ultra geliştirilmiş versiyon
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 20px; 
                    background-color: #f5f5f5; 
                    line-height: 1.6;
                }}
                .container {{ 
                    max-width: 1200px; 
                    margin: 0 auto; 
                    background: white; 
                    border-radius: 10px; 
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); 
                    overflow: hidden;
                }}
                .header {{ 
                    background: linear-gradient(135deg, #dc3545, #c82333); 
                    color: white; 
                    padding: 30px; 
                    text-align: center; 
                }}
                .content {{ 
                    padding: 30px; 
                }}
                .alert {{ 
                    background-color: #f8d7da; 
                    border: 1px solid #f5c6cb; 
                    color: #721c24; 
                    padding: 15px; 
                    border-radius: 5px; 
                    margin: 20px 0; 
                }}
                .info-grid {{ 
                    display: grid; 
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
                    gap: 20px; 
                    margin: 20px 0; 
                }}
                .info-card {{ 
                    background-color: #f8f9fa; 
                    padding: 15px; 
                    border-radius: 5px; 
                    border-left: 4px solid #007bff; 
                }}
                .geo-grid {{ 
                    display: grid; 
                    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
                    gap: 15px; 
                    margin: 15px 0; 
                }}
                .geo-card {{ 
                    background-color: #f8f9fa; 
                    padding: 15px; 
                    border-radius: 8px; 
                    border-left: 4px solid #28a745; 
                }}
                .geo-card h5 {{ 
                    margin: 0 0 10px 0; 
                    color: #155724; 
                    font-size: 14px; 
                }}
                .geo-card p {{ 
                    margin: 5px 0; 
                    font-size: 13px; 
                }}
                .geo-card ul {{ 
                    margin: 5px 0; 
                    padding-left: 15px; 
                    font-size: 13px; 
                }}
                .geolocation-section {{ 
                    background-color: #e8f5e8; 
                    padding: 20px; 
                    border-radius: 8px; 
                    margin: 20px 0; 
                    border: 1px solid #c3e6cb; 
                }}
                .geolocation-section h4 {{ 
                    color: #155724; 
                    margin-top: 0; 
                }}
                .browser-analysis {{ 
                    background-color: #e3f2fd; 
                    padding: 20px; 
                    border-radius: 8px; 
                    margin: 20px 0; 
                    border: 1px solid #bbdefb; 
                }}
                .browser-analysis h4 {{ 
                    color: #0d47a1; 
                    margin-top: 0; 
                }}
                .request-analysis {{ 
                    background-color: #fce4ec; 
                    padding: 20px; 
                    border-radius: 8px; 
                    margin: 20px 0; 
                    border: 1px solid #f8bbd9; 
                }}
                .request-analysis h4 {{ 
                    color: #880e4f; 
                    margin-top: 0; 
                }}
                .security-recommendations {{ 
                    background-color: #fff3e0; 
                    padding: 15px; 
                    border-radius: 8px; 
                    margin: 15px 0; 
                    border: 1px solid #ffcc02; 
                }}
                .additional-services {{ 
                    background-color: #f3e5f5; 
                    padding: 15px; 
                    border-radius: 8px; 
                    margin: 15px 0; 
                }}
                .service-info {{ 
                    margin: 8px 0; 
                    font-size: 13px; 
                }}
                .geo-info-error {{ 
                    background-color: #f8d7da; 
                    padding: 15px; 
                    border-radius: 8px; 
                    border: 1px solid #f5c6cb; 
                    color: #721c24; 
                }}
                .code {{ 
                    background-color: #f1f3f4; 
                    padding: 10px; 
                    border-radius: 5px; 
                    font-family: 'Courier New', monospace; 
                    margin: 10px 0; 
                    word-break: break-all;
                    font-size: 12px;
                }}
                .footer {{ 
                    background-color: #f8f9fa; 
                    padding: 20px; 
                    text-align: center; 
                    color: #6c757d; 
                }}
                h1, h2, h3 {{ margin-top: 0; }}
                .status {{ 
                    display: inline-block; 
                    padding: 5px 10px; 
                    border-radius: 15px; 
                    font-size: 12px; 
                    font-weight: bold; 
                    text-transform: uppercase; 
                }}
                .status-kritik {{ background-color: #dc3545; color: white; }}
                .status-yüksek {{ background-color: #fd7e14; color: white; }}
                .status-orta {{ background-color: #ffc107; color: black; }}
                
                /* Responsive design for mobile */
                @media (max-width: 768px) {{
                    .info-grid, .geo-grid {{ 
                        grid-template-columns: 1fr; 
                    }}
                    .container {{ 
                        margin: 10px; 
                        border-radius: 5px; 
                    }}
                    .content {{ 
                        padding: 15px; 
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{attack_info['icon']} ADVANCED GÜVENLİK ALARMI</h1>
                    <h2>{attack_info['name']}</h2>
                    <span class="status status-{attack_info['severity'].lower()}">{attack_info['severity']} SEVİYE TEHDİT</span>
                </div>
                
                <div class="content">
                    <div class="alert">
                        <strong>🚨 KRİTİK UYARI:</strong> Sitenizde gelişmiş bir güvenlik saldırısı tespit edildi ve engellenmiştir. Detaylı analiz aşağıda yer almaktadır.
                    </div>
                    
                    <h3>📊 Saldırı Detayları</h3>
                    <div class="info-grid">
                        <div class="info-card">
                            <strong>🕒 Tarih/Saat:</strong><br>
                            {request_info['timestamp']}
                        </div>
                        <div class="info-card">
                            <strong>🌐 IP Adresi:</strong><br>
                            {request_info['ip']}
                        </div>
                        <div class="info-card">
                            <strong>🖥️ Hostname:</strong><br>
                            {request_info['hostname']}
                        </div>
                        <div class="info-card">
                            <strong>📝 HTTP Metodu:</strong><br>
                            {request_info['method']}
                        </div>
                    </div>
                    
                    {geo_section}
                    
                    {browser_info}
                    
                    {size_info}
                    
                    <h3>🎯 Hedef Bilgileri</h3>
                    <div class="code">
                        <strong>URL:</strong> {request_info['path']}<br>
                        <strong>Saldırı Türü:</strong> {attack_info['name']}<br>
                        <strong>Açıklama:</strong> {attack_info['description']}<br>
                        <strong>Güvenlik Seviyesi:</strong> {attack_info['severity']}
                    </div>
                    
                    <h3>🔍 İstek Detayları</h3>
                    <div class="code">
                        <strong>User-Agent:</strong><br>
                        {request_info['user_agent'][:300]}{'...' if len(str(request_info['user_agent'])) > 300 else ''}
                    </div>
                    
                    {headers_info}
                    
                    {f'<h3>📋 GET Parametreleri</h3><div class="code">{safe_json_dumps(request_info["get_params"])}</div>' if request_info.get('get_params') else ''}
                    
                    {f'<h3>📋 POST Parametreleri</h3><div class="code">{safe_json_dumps(request_info["post_params"])}</div>' if request_info.get('post_params') else ''}
                    
                    {session_section}
                    
                    {f'<h3>ℹ️ Ek Bilgiler</h3><div class="code">{additional_info}</div>' if additional_info else ''}
                    
                    <div class="alert">
                        <strong>🛡️ Güvenlik Durumu:</strong> Saldırı başarıyla engellenmiştir. Sistem güvenliği sağlanmıştır. Gelişmiş analiz ve izleme aktif durumda.
                    </div>
                </div>
                
                <div class="footer">
                    <p>🤖 Bu e-posta gelişmiş otomatik güvenlik sistemi tarafından gönderilmiştir.</p>
                    <p>📧 Advanced Security System | {datetime.now().strftime('%Y')}</p>
                    <p>🔗 IP Bilgileri: Çoklu servis kullanılarak detaylı analiz yapılmıştır</p>
                    <p>⚡ Gerçek zamanlı tehdit tespiti ve analizi aktif</p>
                </div>
            </div>
        </body>
        </html>
        """
        return html_content
    
    def send_email_async(self, subject, html_content):
        """E-postayı asenkron olarak gönder"""
        def send_email():
            try:
                # E-posta ayarlarını kontrol et
                if not all([self.sender_email, self.sender_password, self.recipient_email]):
                    logger.error("E-posta ayarları eksik. E-posta gönderilemiyor.")
                    return
                
                # E-posta mesajını oluştur
                msg = MIMEMultipart('alternative')
                msg['Subject'] = subject
                msg['From'] = self.sender_email
                msg['To'] = self.recipient_email
                
                # HTML içeriği ekle
                html_part = MIMEText(html_content, 'html', 'utf-8')
                msg.attach(html_part)
                
                # SMTP ile gönder
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.sender_email, self.sender_password)
                    server.send_message(msg)
                
                logger.info(f"Gelişmiş güvenlik bildirimi e-postası başarıyla gönderildi: {self.recipient_email}")
                
            except smtplib.SMTPAuthenticationError:
                logger.error("SMTP kimlik doğrulama hatası. E-posta ayarlarını kontrol edin.")
            except smtplib.SMTPException as e:
                logger.error(f"SMTP hatası: {str(e)}")
            except Exception as e:
                logger.error(f"E-posta gönderme hatası: {str(e)}")
        
        # Thread ile asenkron gönder
        if self.email_enabled:
            email_thread = Thread(target=send_email)
            email_thread.daemon = True
            email_thread.start()
    
    def should_send_notification(self, ip, attack_type):
        """Bildirimi gönderilmeli mi kontrol et (spam önleme)"""
        cache_key = f"security_notification:{ip}:{attack_type}"
        last_notification = cache.get(cache_key)
        
        # Son 3 dakika içinde aynı IP ve saldırı türü için bildirim gönderilmişse skip et
        if last_notification:
            return False
        
        # Cache'e kaydet (3 dakika - daha sık bildirim için)
        cache.set(cache_key, True, 180)
        return True
    
    def detect_attack_from_response(self, request, response):
        """Response'dan saldırı tespiti yap - status code bazlı"""
        # Response status koduna göre doğrudan saldırı türü belirle
        if response.status_code == 429:  # Rate limit
            return 'RATE_LIMIT'
        elif response.status_code == 403:  # Permission denied  
            return 'BRUTEFORCE'
        elif response.status_code == 400:  # Bad request - içerik analizi yap
            # Sadece 400 durumunda içerik analizi yap
            request_info = self.get_extended_client_info(request)
            detected_attack = self.detect_attack_type(request_info)
            # UNKNOWN ise döndürme, gerçek saldırı tespiti varsa döndür
            return detected_attack if detected_attack != 'UNKNOWN' else None
        
        return None
    
    def process_request(self, request):
        """İsteği işle ve saldırı tespiti yap - Geliştirilmiş versiyon"""
        # E-posta bildirimi devre dışıysa çık
        if not self.email_enabled:
            return None
        
        # Genişletilmiş istek içeriğini analiz et
        request_info = self.get_extended_client_info(request)
        attack_type = self.detect_attack_type(request_info)
        
        # Saldırı tespit edilmişse ve bilinmeyen değilse
        if attack_type and attack_type != 'UNKNOWN':
            # Spam önleme kontrolü
            if self.should_send_notification(request_info['ip'], attack_type):
                # E-posta içeriğini oluştur - geliştirilmiş versiyon
                subject = f"🚨 ADVANCED GÜVENLİK ALARMI - {self.attack_types[attack_type]['name']}"
                
                additional_info = f"""Request Method: {request.method}
Full Path: {request.get_full_path()}
Connection Info: {request_info.get('connection_info', {})}
Request Size: {request_info.get('request_size', {}).get('total_bytes', 0)} bytes
Browser Analysis: {request_info.get('browser_analysis', {}).get('browser', 'Unknown')}
Threat Level: {request_info.get('geolocation', {}).get('reputation', {}).get('threat_level', 'LOW')}"""
                
                html_content = self.create_enhanced_email_content(attack_type, request_info, additional_info)
                
                # E-postayı asenkron gönder
                self.send_email_async(subject, html_content)
                
                # Log kaydet - geliştirilmiş geolocation bilgisi ile
                geo_info = request_info.get('geolocation', {})
                location_str = ""
                threat_info = ""
                
                if geo_info and geo_info.get('status') == 'success':
                    city = geo_info.get('city', 'N/A')
                    country = geo_info.get('country', 'N/A')
                    isp = geo_info.get('isp', 'N/A')
                    location_str = f", Konum: {city}/{country}, ISP: {isp}"
                    
                    reputation = geo_info.get('reputation', {})
                    if reputation.get('threat_types'):
                        threat_info = f", Tehditler: {', '.join(reputation['threat_types'])}"
                
                browser_info = request_info.get('browser_analysis', {})
                browser_str = f", Browser: {browser_info.get('browser', 'Unknown')}"
                
                logger.warning(
                    f"ADVANCED - Güvenlik saldırısı tespit edildi ve detaylı bildirim gönderildi. "
                    f"IP: {request_info['ip']}{location_str}{threat_info}{browser_str}, "
                    f"Saldırı: {attack_type}, URL: {request_info['path']}, "
                    f"Request Size: {request_info.get('request_size', {}).get('total_bytes', 0)} bytes"
                )
        
        return None
    
    def process_response(self, request, response):
        """Response işlendikten sonra güvenlik kontrolü yap - Geliştirilmiş versiyon"""
        # E-posta bildirimi devre dışıysa çık
        if not self.email_enabled:
            return response
        
        # Güvenlik ihlali tespit edilmişse
        attack_type = self.detect_attack_from_response(request, response)
        
        if attack_type:
            request_info = self.get_extended_client_info(request)
            
            # Spam önleme kontrolü
            if self.should_send_notification(request_info['ip'], attack_type):
                # E-posta içeriğini oluştur - geliştirilmiş versiyon
                subject = f"🚨 ADVANCED GÜVENLİK ALARMI - {self.attack_types[attack_type]['name']}"
                
                additional_info = f"""Response Status Code: {response.status_code}
Response Analysis: Status-based detection
Request Analysis: {request_info.get('request_size', {})}
Browser Fingerprint: {request_info.get('browser_analysis', {})}
Geolocation Threat Level: {request_info.get('geolocation', {}).get('reputation', {}).get('threat_level', 'LOW')}"""
                
                if hasattr(response, 'content') and response.content:
                    try:
                        content_preview = str(response.content[:300], 'utf-8', errors='ignore')
                        additional_info += f"\nResponse Content Preview: {content_preview}"
                    except:
                        additional_info += "\nResponse Content: [Binary content]"
                
                html_content = self.create_enhanced_email_content(attack_type, request_info, additional_info)
                
                # E-postayı asenkron gönder
                self.send_email_async(subject, html_content)
                
                # Log kaydet - geliştirilmiş geolocation bilgisi ile
                geo_info = request_info.get('geolocation', {})
                location_str = ""
                threat_info = ""
                
                if geo_info and geo_info.get('status') == 'success':
                    city = geo_info.get('city', 'N/A')
                    country = geo_info.get('country', 'N/A')
                    isp = geo_info.get('isp', 'N/A')
                    location_str = f", Konum: {city}/{country}, ISP: {isp}"
                    
                    reputation = geo_info.get('reputation', {})
                    if reputation.get('threat_types'):
                        threat_info = f", Tehditler: {', '.join(reputation['threat_types'])}"
                
                browser_info = request_info.get('browser_analysis', {})
                browser_str = f", Browser: {browser_info.get('browser', 'Unknown')}"
                
                logger.warning(
                    f"ADVANCED - Güvenlik saldırısı tespit edildi ve detaylı bildirim gönderildi. "
                    f"IP: {request_info['ip']}{location_str}{threat_info}{browser_str}, "
                    f"Saldırı: {attack_type}, URL: {request_info['path']}, "
                    f"Status: {response.status_code}"
                )
        
        return response
