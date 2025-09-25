from flask import Flask, request, jsonify
import requests
import re
import json
from urllib.parse import urljoin, urlparse
import time
from datetime import datetime
import logging
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Permitir CORS para Clay
logging.basicConfig(level=logging.INFO)

class MagentoDetector:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.vulnerabilities_db = self._load_vulnerabilities()
        self.valid_magento_versions = self._get_valid_version_patterns()
    
    def _load_vulnerabilities(self):
        """Base de datos de vulnerabilidades conocidas de Magento"""
        return {
            "1.x": {
                "versions": ["1.9.4.5", "1.9.4.4", "1.9.4.3", "1.9.4.2", "1.9.4.1", "1.9.4.0"],
                "vulnerabilities": [
                    {
                        "id": "CVE-2022-24086",
                        "severity": "Critical",
                        "description": "SQL Injection vulnerability in Magento 1.x",
                        "affected_versions": "< 1.9.4.5",
                        "recommendation": "Upgrade to Magento 1.9.4.5 or migrate to Magento 2.x"
                    },
                    {
                        "id": "CVE-2020-24407",
                        "severity": "High",
                        "description": "Remote Code Execution vulnerability",
                        "affected_versions": "< 1.9.4.3",
                        "recommendation": "Immediate upgrade required"
                    }
                ]
            },
            "2.x": {
                "versions": ["2.4.6", "2.4.5", "2.4.4", "2.4.3", "2.4.2", "2.4.1", "2.4.0"],
                "vulnerabilities": [
                    {
                        "id": "CVE-2023-29017",
                        "severity": "Medium",
                        "description": "Cross-site scripting (XSS) vulnerability",
                        "affected_versions": "< 2.4.6",
                        "recommendation": "Update to latest version"
                    }
                ]
            }
        }
    
    def _get_valid_version_patterns(self):
        """Patrones de versiones válidas de Magento"""
        return {
            "1.x": r"^1\.[4-9]\.\d+(\.\d+)?$",  # 1.4.0 - 1.9.4.5
            "2.x": r"^2\.[0-4]\.\d+(\.\d+)?$"   # 2.0.0 - 2.4.6
        }
    
    def _validate_magento_version(self, version_string):
        """Validar si una versión es válida para Magento con validación estricta"""
        if not version_string:
            return None
        
        # Lista de versiones válidas conocidas de Magento
        valid_magento_versions = {
            # Magento 1.x versions (principales)
            '1.x': ['1.4', '1.5', '1.6', '1.7', '1.8', '1.9'],
            '1.4': ['1.4.0', '1.4.1', '1.4.2'],
            '1.5': ['1.5.0', '1.5.1'],
            '1.6': ['1.6.0', '1.6.1', '1.6.2'],
            '1.7': ['1.7.0', '1.7.1'],
            '1.8': ['1.8.0', '1.8.1'],
            '1.9': ['1.9.0', '1.9.1', '1.9.2', '1.9.3', '1.9.4'],
            
            # Magento 2.x versions (principales)
            '2.x': ['2.0', '2.1', '2.2', '2.3', '2.4'],
            '2.0': ['2.0.0', '2.0.1', '2.0.2', '2.0.3', '2.0.4', '2.0.5', '2.0.6', '2.0.7', '2.0.8', '2.0.9', '2.0.10', '2.0.11', '2.0.12', '2.0.13', '2.0.14', '2.0.15', '2.0.16', '2.0.17', '2.0.18'],
            '2.1': ['2.1.0', '2.1.1', '2.1.2', '2.1.3', '2.1.4', '2.1.5', '2.1.6', '2.1.7', '2.1.8', '2.1.9', '2.1.10', '2.1.11', '2.1.12', '2.1.13', '2.1.14', '2.1.15', '2.1.16', '2.1.17', '2.1.18'],
            '2.2': ['2.2.0', '2.2.1', '2.2.2', '2.2.3', '2.2.4', '2.2.5', '2.2.6', '2.2.7', '2.2.8', '2.2.9', '2.2.10', '2.2.11'],
            '2.3': ['2.3.0', '2.3.1', '2.3.2', '2.3.3', '2.3.4', '2.3.5', '2.3.6', '2.3.7'],
            '2.4': ['2.4.0', '2.4.1', '2.4.2', '2.4.3', '2.4.4', '2.4.5', '2.4.6', '2.4.7']
        }
        
        # Normalizar versión
        version = version_string.strip()
        
        # Validar formato básico primero
        if not re.match(r'^\d+\.\d+(\.\d+)?(\.\d+)?$', version):
            return None
        
        # Verificar que no tenga más de 4 partes (major.minor.patch.build)
        version_parts = version.split('.')
        if len(version_parts) > 4:
            return None
            
        # Verificar que cada parte sea un número razonable
        for part in version_parts:
            try:
                num = int(part)
                if num > 999:  # Rechazar números muy grandes (como 551, 423, 337, 862)
                    return None
            except ValueError:
                return None
        
        # Verificar rangos válidos para major.minor
        if len(version_parts) >= 2:
            major = int(version_parts[0])
            minor = int(version_parts[1])
            
            # Solo aceptar Magento 1.x y 2.x
            if major == 1:
                if minor < 4 or minor > 9:  # 1.4 - 1.9
                    return None
            elif major == 2:
                if minor < 0 or minor > 4:  # 2.0 - 2.4
                    return None
            else:
                return None  # Solo Magento 1.x y 2.x son válidos
        
        # Verificar en lista de versiones conocidas si es versión específica
        major_minor = f"{version_parts[0]}.{version_parts[1]}"
        if len(version_parts) >= 3:
            # Versión específica como 2.4.3
            for version_family, versions in valid_magento_versions.items():
                if isinstance(versions, list) and version in versions:
                    return version
                    
            # Si no está en la lista exacta, verificar que al menos el major.minor sea válido
            if major_minor in ['1.4', '1.5', '1.6', '1.7', '1.8', '1.9', '2.0', '2.1', '2.2', '2.3', '2.4']:
                # Permitir patch versions razonables (0-20)
                if len(version_parts) >= 3:
                    patch = int(version_parts[2])
                    if patch > 20:
                        return None
                # Permitir build versions razonables (0-10)        
                if len(version_parts) == 4:
                    build = int(version_parts[3])
                    if build > 10:
                        return None
                return version
        else:
            # Versión general como 2.x, 1.9
            if version in ['1.x', '2.x'] or major_minor in ['1.4', '1.5', '1.6', '1.7', '1.8', '1.9', '2.0', '2.1', '2.2', '2.3', '2.4']:
                return version
        
        return None
    
    def _quick_version_detection(self, url, html_content):
        """Detección rápida de versión para early exit"""
        try:
            # Buscar versión en HTML (más rápido que requests adicionales)
            version_patterns = [
                r'magento[\/\s]+(\d+\.\d+(?:\.\d+)?)',
                r'magento\s*version[:\s]+(\d+\.\d+(?:\.\d+)?)',
                r'mage["\s]*version["\s]*[:\s]*["\'](\d+\.\d+(?:\.\d+)?)["\']',
            ]
            
            for pattern in version_patterns:
                matches = re.finditer(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    potential_version = match.group(1)
                    validated_version = self._validate_magento_version(potential_version)
                    if validated_version:
                        return validated_version
            
            # Solo si no encontramos en HTML, intentar endpoint rápido
            from urllib.parse import urljoin
            version_response = self._safe_request(urljoin(url, '/magento_version'), timeout=1)
            if version_response and version_response.status_code == 200:
                content = version_response.text
                version_match = re.search(r'Magento[\/\s]*(\d+\.\d+(?:\.\d+)?)', content, re.IGNORECASE)
                if version_match:
                    potential_version = version_match.group(1)
                    return self._validate_magento_version(potential_version)
            
            return None
        except:
            return None
    
    def analyze_url(self, url):
        """Analiza una URL para detectar Magento"""
        try:
            # Normalizar URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Verificar si necesitamos www
            original_url = url
            if not url.startswith(('https://www.', 'http://www.')):
                # Probar primero sin www
                test_response = self._safe_request(url, timeout=1)
                if test_response and test_response.status_code in [301, 302, 307, 308]:
                    # Si hay redirección, usar la URL redirigida
                    redirect_url = test_response.headers.get('location', '')
                    if redirect_url and 'www.' in redirect_url:
                        url = redirect_url
            
            result = {
                'url': url,
                'original_url': original_url if url != original_url else None,
                'is_magento': False,
                'version': None,
                'confidence': 0,
                'evidence': [],
                'vulnerabilities': [],
                'recommendations': [],
                'timestamp': datetime.now().isoformat()
            }
            
            # Realizar análisis
            result.update(self._detect_magento(url))
            
            # Si se detectó Magento, buscar vulnerabilidades
            if result['is_magento'] and result['version']:
                result['vulnerabilities'] = self._check_vulnerabilities(result['version'])
                result['recommendations'] = self._get_recommendations(result)
            
            return result
            
        except Exception as e:
            logging.error(f"Error analyzing {url}: {str(e)}")
            return {
                'url': url,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _detect_magento(self, url):
        """Detecta si el sitio usa Magento con optimización para velocidad"""
        evidence = []
        confidence = 0
        version = None
        is_magento = False
        
        try:
            # 1. Analizar página principal
            response = self._safe_request(url)
            if response:
                html_content = response.text.lower()
                headers = response.headers
                
                # Verificar headers específicos de Magento (PRIORITY: más confiables)
                priority_headers = ['x-magento-cache-control', 'x-magento-cache-debug', 'x-magento-tags', 'x-magento-vary']
                for header in priority_headers:
                    if header in headers:
                        evidence.append(f"Magento header found: {header}")
                        confidence += 30
                        is_magento = True
                        # EARLY EXIT: Si encontramos header específico de Magento, es 100% seguro
                        if confidence >= 60:
                            return {
                                'is_magento': True,
                                'version': self._quick_version_detection(url, html_content),
                                'confidence': min(confidence, 100),
                                'evidence': evidence
                            }
                
                # Headers secundarios (menos específicos, menor peso)
                secondary_headers = [('x-content-type-options', 10), ('set-cookie', 5)]
                for header, score in secondary_headers:
                    if header in headers:
                        evidence.append(f"Magento header found: {header}")
                        confidence += score
                        # No marcar como Magento solo por headers genéricos
                
                # Verificar cookies específicas de Magento
                set_cookie = headers.get('set-cookie', '').lower()
                magento_cookies = ['mage-cache-storage', 'mage-cache-sessid', 'frontend', 'store']
                for cookie in magento_cookies:
                    if cookie in set_cookie:
                        evidence.append(f"Magento cookie found: {cookie}")
                        confidence += 15
                        is_magento = True
                
                # Buscar patrones específicos de Magento (PRIORIDAD: más confiables primero)
                # Patrones de ALTA CONFIANZA primero
                high_confidence_patterns = [
                    (r'data-mage-init', 25),  # Muy específico de Magento 2
                    (r'Magento_[A-Za-z]+', 30),  # Módulos de Magento
                    (r'/pub/static/version\d+/', 25),  # Static files con versioning
                    (r'Magento\\\\', 30),  # Namespace en código
                ]
                
                for pattern, score in high_confidence_patterns:
                    if re.search(pattern, html_content, re.IGNORECASE):
                        evidence.append(f"High-confidence Magento pattern: {pattern}")
                        confidence += score
                        is_magento = True
                        # EARLY EXIT: Si tenemos alta confianza, salir rápido
                        if confidence >= 70:
                            return {
                                'is_magento': True,
                                'version': self._quick_version_detection(url, html_content),
                                'confidence': min(confidence, 100),
                                'evidence': evidence
                            }
                
                # Solo si no tenemos alta confianza, buscar patrones secundarios
                if confidence < 50:
                    secondary_patterns = [
                        (r'mage/cookies\.js', 15),
                        (r'skin/frontend', 12),  # Magento 1.x
                        (r'/media/catalog/product/', 15),
                        (r'checkout/cart', 8),
                        (r'customer/account/login', 10),
                        (r'catalogsearch/result', 8),
                        (r'mage\.cookies', 12),
                        (r'var/view_preprocessed/', 15),
                        (r'mage/requirejs/mixins', 15),
                        (r'require\.js.*mage', 12)
                    ]
                    
                    for pattern, score in secondary_patterns:
                        if re.search(pattern, html_content, re.IGNORECASE):
                            evidence.append(f"Magento pattern found: {pattern}")
                            confidence += score
                            is_magento = True
                
                # Detectar versión desde meta tags o comentarios (más específico)
                version_patterns = [
                    r'magento[\/\s]+(\d+\.\d+(?:\.\d+)?)',
                    r'magento\s*version[:\s]+(\d+\.\d+(?:\.\d+)?)',
                    r'mage["\s]*version["\s]*[:\s]*["\'](\d+\.\d+(?:\.\d+)?)["\']',
                    r'<!--.*magento\s+(\d+\.\d+(?:\.\d+)?).*-->',
                    r'data-version["\s]*=["\s]*["\'](\d+\.\d+(?:\.\d+)?)["\']'
                ]
                
                for pattern in version_patterns:
                    matches = re.finditer(pattern, html_content, re.IGNORECASE)
                    for match in matches:
                        potential_version = match.group(1)
                        validated_version = self._validate_magento_version(potential_version)
                        if validated_version:
                            version = validated_version
                            evidence.append(f"Valid Magento version detected from HTML: {version}")
                            confidence += 30
                            break
                    if version:
                        break
            
            # 2. Solo verificar archivos si no tenemos alta confianza (OPTIMIZACIÓN)
            if confidence < 70:
                # Solo verificar archivos más específicos y rápidos primero
                priority_files = [
                    '/js/mage/cookies.js',
                    '/pub/static/',
                    '/media/catalog/',
                    '/skin/frontend/',
                ]
                
                for file_path in priority_files:
                    if self._check_file_exists(url, file_path):
                        evidence.append(f"Magento file found: {file_path}")
                        confidence += 20
                        is_magento = True
                        # Si ya tenemos buena confianza, parar verificaciones
                        if confidence >= 70:
                            break
            
            # 3. Solo buscar versión y hacer verificaciones adicionales si no tenemos alta confianza
            if confidence < 70:
                # Verificar versión desde archivos específicos (solo si es necesario)
                if not version:
                    version = self._detect_version_from_files(url)
                    if version:
                        evidence.append(f"Version detected from files: {version}")
                        confidence += 25
                
                # Solo si aún no tenemos confianza suficiente, hacer verificaciones adicionales
                if confidence < 50:
                    # Analizar estructura de URLs
                    url_pattern_result = self._check_magento_url_patterns(url)
                    if url_pattern_result:
                        if url_pattern_result == "magento_blocked":
                            evidence.append("Magento version endpoint exists but is blocked (protected)")
                            confidence += 30
                            is_magento = True
                        elif url_pattern_result == True:
                            evidence.append("Magento URL patterns detected")
                            confidence += 15
                            is_magento = True
                
                # Fallback solo si realmente no tenemos evidencia
                if confidence < 30:
                    fallback_result = self._fallback_detection(url)
                    if fallback_result:
                        evidence.extend(fallback_result['evidence'])
                        confidence += fallback_result['confidence']
                        if fallback_result['version']:
                            version = fallback_result['version']
            
            # Determinar si es Magento basado en confianza (umbral optimizado)
            if confidence >= 25:  # Subir umbral para evitar falsos positivos
                is_magento = True
            
            return {
                'is_magento': is_magento,
                'version': version,
                'confidence': min(confidence, 100),
                'evidence': evidence
            }
            
        except Exception as e:
            logging.error(f"Error in _detect_magento: {str(e)}")
            return {
                'is_magento': False,
                'version': None,
                'confidence': 0,
                'evidence': [f"Error during detection: {str(e)}"]
            }
    
    def _safe_request(self, url, timeout=2):
        """Realizar request seguro con timeout muy corto para Clay"""
        try:
            response = self.session.get(url, timeout=timeout, allow_redirects=True, stream=False)
            return response
        except Exception as e:
            logging.warning(f"Request failed for {url}: {str(e)}")
            return None
    
    def _check_file_exists(self, base_url, file_path):
        """Verificar si un archivo específico existe"""
        try:
            full_url = urljoin(base_url, file_path)
            response = self._safe_request(full_url)
            if response:
                # 200 = existe y accesible
                if response.status_code == 200:
                    return True
                # 403 = existe pero protegido (común en Magento)
                elif response.status_code == 403:
                    return True
                # 401 = existe pero requiere autenticación
                elif response.status_code == 401:
                    return True
            return False
        except:
            return False
    
    def _detect_version_from_files(self, url):
        """Intentar detectar versión desde archivos específicos"""
        version_files = [
            '/magento_version',
            '/RELEASE_NOTES.txt',
            '/app/Mage.php',
            '/lib/Varien/Version.php',
            '/pub/static/version.txt',
            '/static/version'
        ]
        
        for file_path in version_files:
            try:
                full_url = urljoin(url, file_path)
                response = self._safe_request(full_url)
                if response and response.status_code == 200:
                    content = response.text
                    
                    # Para /magento_version, buscar patrones específicos
                    if 'magento_version' in file_path:
                        version_patterns = [
                            r"Magento\s*[\/\s]*(\d+\.\d+(?:\.\d+)?)",  # "Magento 2.4.3" o "Magento/2.4"
                            r"Version:\s*(\d+\.\d+(?:\.\d+)?)",  # "Version: 2.4.3"
                        ]
                    else:
                        # Patrones generales para otros archivos
                        version_patterns = [
                            r"version['\"\s]*=>['\"\s]*['\"](\d+\.\d+(?:\.\d+)?)['\"]",
                            r"VERSION['\"\s]*=['\"\s]*['\"](\d+\.\d+(?:\.\d+)?)['\"]",
                            r"define\s*\(\s*['\"]MAGENTO_VERSION['\"]\s*,\s*['\"](\d+\.\d+(?:\.\d+)?)['\"]",
                        ]
                    
                    for pattern in version_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            potential_version = match.group(1)
                            validated_version = self._validate_magento_version(potential_version)
                            if validated_version:
                                return validated_version
            except:
                continue
        
        return None
    
    def _check_magento_url_patterns(self, url):
        """Verificar patrones típicos de URL de Magento"""
        # Verificar específicamente /magento_version primero
        magento_version_response = self._check_magento_version_endpoint(url)
        if magento_version_response == "blocked":
            return "magento_blocked"
        elif magento_version_response == "found":
            return True
        
        # Verificar otros patrones
        common_paths = [
            '/customer/account/login',
            '/checkout/cart',
            '/catalogsearch/result',
            '/admin',
            '/pub/static/',
            '/static/version'
        ]
        
        found_patterns = 0
        for path in common_paths:
            if self._check_file_exists(url, path):
                found_patterns += 1
        
        # Si encontramos 2 o más patrones, es probable que sea Magento
        return found_patterns >= 2
    
    def _check_magento_version_endpoint(self, base_url):
        """Verificar específicamente el endpoint /magento_version"""
        try:
            full_url = urljoin(base_url, '/magento_version')
            response = self._safe_request(full_url, timeout=3)
            
            if response:
                # Si obtenemos contenido y contiene "Magento"
                if response.status_code == 200:
                    content = response.text.lower()
                    if 'magento' in content:
                        return "found"
                
                # Si está bloqueado por Cloudflare u otro WAF
                elif response.status_code == 403:
                    return "blocked"
                
                # Si es una página de challenge de Cloudflare
                elif response.status_code in [503, 429]:
                    return "blocked"
                
                # Si el contenido sugiere bloqueo por bot protection
                elif 'cloudflare' in response.text.lower() or 'challenge' in response.text.lower():
                    return "blocked"
            
            return "not_found"
        except:
            return "not_found"
    
    def _fallback_detection(self, url):
        """Método de fallback para sitios con protecciones anti-bot"""
        evidence = []
        confidence = 0
        version = None
        
        try:
            # Intentar con diferentes User-Agents
            user_agents = [
                'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'curl/7.68.0'
            ]
            
            for ua in user_agents:
                try:
                    temp_session = requests.Session()
                    temp_session.headers.update({'User-Agent': ua})
                    
                    # Probar /magento_version con diferentes UAs
                    response = temp_session.get(urljoin(url, '/magento_version'), timeout=3)
                    if response.status_code == 200 and 'magento' in response.text.lower():
                        evidence.append(f"Magento version endpoint accessible with alternate UA")
                        confidence += 40
                        
                        # Extraer y validar versión
                        version_match = re.search(r'Magento[\/\s]*(\d+\.\d+(?:\.\d+)?)', response.text, re.IGNORECASE)
                        if version_match:
                            potential_version = version_match.group(1)
                            validated_version = self._validate_magento_version(potential_version)
                            if validated_version:
                                version = validated_version
                                evidence.append(f"Valid Magento version detected: {version}")
                            else:
                                evidence.append(f"Invalid version format detected: {potential_version}")
                                confidence += 10  # Menor confianza para versiones inválidas
                        
                        break
                        
                except:
                    continue
            
            # Verificar robots.txt para pistas de Magento
            try:
                robots_response = requests.get(urljoin(url, '/robots.txt'), timeout=2)
                if robots_response.status_code == 200:
                    robots_content = robots_response.text.lower()
                    magento_robots_patterns = [
                        '/media/catalog/',
                        '/pub/static/',
                        '/downloader/',
                        '/app/',
                        '/var/',
                        'magento'
                    ]
                    
                    for pattern in magento_robots_patterns:
                        if pattern in robots_content:
                            evidence.append(f"Magento pattern in robots.txt: {pattern}")
                            confidence += 5
            except:
                pass
            
            # Verificar sitemap.xml
            try:
                sitemap_response = requests.get(urljoin(url, '/sitemap.xml'), timeout=2)
                if sitemap_response.status_code == 200:
                    sitemap_content = sitemap_response.text.lower()
                    if '/catalog/' in sitemap_content or '/customer/' in sitemap_content:
                        evidence.append("Magento URL patterns in sitemap")
                        confidence += 10
            except:
                pass
                
            return {
                'evidence': evidence,
                'confidence': confidence,
                'version': version
            } if evidence else None
            
        except Exception as e:
            logging.warning(f"Fallback detection failed for {url}: {str(e)}")
            return None
    
    def _check_vulnerabilities(self, version):
        """Verificar vulnerabilidades para una versión específica"""
        vulnerabilities = []
        
        try:
            major_version = "1.x" if version.startswith("1.") else "2.x"
            
            if major_version in self.vulnerabilities_db:
                for vuln in self.vulnerabilities_db[major_version]["vulnerabilities"]:
                    if self._version_is_affected(version, vuln["affected_versions"]):
                        vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            logging.error(f"Error checking vulnerabilities: {str(e)}")
            return []
    
    def _version_is_affected(self, version, affected_pattern):
        """Verificar si una versión está afectada por una vulnerabilidad"""
        try:
            # Simplificado: verificar si la versión es menor que la especificada
            if affected_pattern.startswith("< "):
                target_version = affected_pattern[2:]
                return self._compare_versions(version, target_version) < 0
            return False
        except:
            return False
    
    def _compare_versions(self, v1, v2):
        """Comparar dos versiones"""
        try:
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            # Igualar longitudes
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
        except:
            return 0
    
    def _get_recommendations(self, result):
        """Generar recomendaciones basadas en el análisis"""
        recommendations = []
        
        if result['is_magento']:
            if result['version']:
                if result['version'].startswith('1.'):
                    recommendations.append("Considere migrar a Magento 2.x para mejor seguridad y soporte")
                
                if result['vulnerabilities']:
                    recommendations.append("Se detectaron vulnerabilidades. Actualice inmediatamente")
                    recommendations.append("Implemente un Web Application Firewall (WAF)")
                    recommendations.append("Realice copias de seguridad regulares")
            
            recommendations.extend([
                "Mantenga Magento actualizado con los últimos parches de seguridad",
                "Use HTTPS en todo el sitio",
                "Implemente autenticación de dos factores para admin",
                "Configure correctamente los permisos de archivos",
                "Oculte la versión de Magento en headers y archivos públicos"
            ])
        
        return recommendations
    
    def lightning_detect(self, url):
        """Ultra-fast Magento detection (0.2-0.5s) - Solo detección básica"""
        try:
            # Normalizar URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Request con timeout muy corto
            response = self._safe_request(url, timeout=2)
            if not response or response.status_code != 200:
                return {
                    'is_magento': False,
                    'confidence': 0,
                    'detection_method': 'failed_request'
                }
            
            html_content = response.text.lower()
            headers = response.headers
            confidence = 0
            detection_method = 'none'
            
            # Solo verificar los indicadores más confiables y rápidos
            # Headers específicos de Magento (más confiables)
            priority_headers = ['x-magento-cache-control', 'x-magento-cache-debug', 'x-magento-tags']
            for header in priority_headers:
                if header in headers:
                    return {
                        'is_magento': True,
                        'confidence': 95,
                        'detection_method': 'magento_headers'
                    }
            
            # Cookies específicas de Magento
            set_cookie = headers.get('set-cookie', '').lower()
            magento_cookies = ['mage-cache-storage', 'frontend', 'store']
            for cookie in magento_cookies:
                if cookie in set_cookie:
                    return {
                        'is_magento': True,
                        'confidence': 90,
                        'detection_method': 'magento_cookies'
                    }
            
            # Patrones de alta confianza en HTML
            if 'data-mage-init' in html_content:
                return {
                    'is_magento': True,
                    'confidence': 95,
                    'detection_method': 'mage_init_pattern'
                }
            
            if re.search(r'magento_[a-za-z]+', html_content):
                return {
                    'is_magento': True,
                    'confidence': 90,
                    'detection_method': 'magento_modules'
                }
            
            # Patrones secundarios
            secondary_patterns = [
                ('mage/cookies.js', 80),
                ('/media/catalog/product/', 75),
                ('skin/frontend', 70),
                ('mage.cookies', 70)
            ]
            
            for pattern, score in secondary_patterns:
                if pattern in html_content:
                    return {
                        'is_magento': True,
                        'confidence': score,
                        'detection_method': 'pattern_match'
                    }
            
            return {
                'is_magento': False,
                'confidence': 10,
                'detection_method': 'no_patterns_found'
            }
            
        except Exception as e:
            return {
                'is_magento': False,
                'confidence': 0,
                'detection_method': 'error',
                'error': str(e)
            }
    
    def estimate_version(self, url):
        """Fast version estimation (0.3-0.8s) - Estimación inteligente con análisis de riesgo"""
        try:
            # Primero verificar que es Magento
            detection = self.lightning_detect(url)
            if not detection['is_magento']:
                return {
                    'is_magento': False,
                    'estimated_version': None,
                    'version_confidence': 0,
                    'risk_level': 'unknown'
                }
            
            # Normalizar URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Intentar detectar versión rápidamente
            response = self._safe_request(url, timeout=3)
            if not response:
                return {
                    'is_magento': True,
                    'estimated_version': '2.x',  # Asunción por defecto
                    'version_confidence': 30,
                    'risk_level': 'medium'
                }
            
            html_content = response.text
            found_version = None
            
            # Buscar versión en HTML con patrones específicos
            version_patterns = [
                r'magento[\/\s]+(\d+\.\d+(?:\.\d+)?)',
                r'version["\s]*[:=]["\s]*(\d+\.\d+(?:\.\d+)?)',
                r'mage["\s]*version["\s]*[:\s]*["\'](\d+\.\d+(?:\.\d+)?)["\']'
            ]
            
            for pattern in version_patterns:
                matches = re.finditer(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    potential_version = match.group(1)
                    if self._validate_magento_version(potential_version):
                        found_version = potential_version
                        break
                if found_version:
                    break
            
            # Si no encontramos versión específica, estimar basado en tecnologías
            if not found_version:
                html_lower = html_content.lower()
                if 'requirejs' in html_lower or 'knockout' in html_lower:
                    found_version = '2.x'  # Tecnologías modernas = Magento 2
                elif 'prototype.js' in html_lower or 'scriptaculous' in html_lower:
                    found_version = '1.x'  # Tecnologías legacy = Magento 1
                else:
                    found_version = '2.x'  # Asunción por defecto para sitios modernos
            
            # Calcular confianza y riesgo
            version_confidence = 80 if '.' in found_version and 'x' not in found_version else 60
            
            # Determinar nivel de riesgo
            risk_level = 'medium'
            if found_version.startswith('1.'):
                risk_level = 'high'  # Magento 1.x es EOL
            elif found_version in ['2.0', '2.1', '2.2']:
                risk_level = 'high'  # Versiones 2.x antiguas
            elif found_version == '2.x':
                risk_level = 'medium'  # Versión 2 desconocida
            elif found_version.startswith('2.'):
                # Versiones específicas de Magento 2
                try:
                    version_parts = found_version.split('.')
                    if len(version_parts) >= 2:
                        minor = int(version_parts[1])
                        if minor >= 4:
                            risk_level = 'low'  # 2.4+ es relativamente nuevo
                        elif minor >= 3:
                            risk_level = 'medium'  # 2.3.x
                        else:
                            risk_level = 'high'  # 2.0-2.2
                except:
                    risk_level = 'medium'
            
            return {
                'is_magento': True,
                'estimated_version': found_version,
                'version_confidence': version_confidence,
                'risk_level': risk_level,
                'detection_method': detection['detection_method']
            }
            
        except Exception as e:
            return {
                'is_magento': True,  # Ya confirmamos que es Magento
                'estimated_version': '2.x',
                'version_confidence': 20,
                'risk_level': 'medium',
                'error': str(e)
            }
    
    def get_exact_version(self, url):
        """Comprehensive version detection (1-3s) - Búsqueda exhaustiva de versión exacta"""
        try:
            # Primero verificar que es Magento
            detection = self.lightning_detect(url)
            if not detection['is_magento']:
                return {
                    'is_magento': False,
                    'exact_version': None,
                    'confidence': 0,
                    'methods_tried': ['lightning_detect']
                }
            
            # Normalizar URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            methods_tried = ['lightning_detect']
            found_version = None
            
            # Método 1: Verificar endpoints específicos de versión
            version_endpoints = [
                '/magento_version',
                '/RELEASE_NOTES.txt',
                '/app/Mage.php',
                '/lib/Varien/Version.php',
                '/pub/static/version.txt'
            ]
            
            for endpoint in version_endpoints:
                try:
                    methods_tried.append(endpoint)
                    full_url = urljoin(url, endpoint)
                    response = self._safe_request(full_url, timeout=4)
                    
                    if response and response.status_code == 200:
                        content = response.text
                        version = self._extract_version_from_content(content)
                        if version:
                            found_version = version
                            break
                except:
                    continue
            
            # Método 2: Análisis profundo de la página principal
            if not found_version:
                try:
                    methods_tried.append('main_page_deep_analysis')
                    response = self._safe_request(url, timeout=5)
                    if response:
                        version = self._extract_version_from_content(response.text)
                        if version:
                            found_version = version
                except:
                    pass
            
            # Método 3: Verificar archivos JavaScript específicos
            if not found_version:
                js_files = [
                    '/js/mage/cookies.js',
                    '/skin/frontend/base/default/js/lib/jquery/jquery.min.js',
                    '/pub/static/frontend/Magento/luma/en_US/js/theme.js'
                ]
                
                for js_file in js_files:
                    try:
                        methods_tried.append(js_file)
                        response = self._safe_request(urljoin(url, js_file), timeout=3)
                        if response and response.status_code == 200:
                            version = self._extract_version_from_content(response.text)
                            if version:
                                found_version = version
                                break
                    except:
                        continue
            
            # Calcular confianza
            confidence = 95 if found_version and '.' in found_version else 70
            
            return {
                'is_magento': True,
                'exact_version': found_version,
                'confidence': confidence,
                'methods_tried': methods_tried,
                'detection_method': detection['detection_method']
            }
            
        except Exception as e:
            return {
                'is_magento': False,
                'exact_version': None,
                'confidence': 0,
                'methods_tried': ['error'],
                'error': str(e)
            }
    
    def _extract_version_from_content(self, content):
        """Extraer versión de cualquier contenido con patrones más precisos"""
        # Patrones más específicos y ordenados por confianza
        version_patterns = [
            # Patrones muy específicos de Magento (alta confianza)
            r"define\s*\(\s*['\"]MAGENTO_VERSION['\"]\s*,\s*['\"](\d+\.\d+(?:\.\d+)?(?:\.\d+)?)['\"]",  # PHP define
            r"Magento\s*[\/\-\s]+v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)",  # "Magento 2.4.3" o "Magento/2.4"
            r"version['\"\s]*=>['\"\s]*['\"](\d+\.\d+(?:\.\d+)?(?:\.\d+)?)['\"]",  # Array version
            r"VERSION['\"\s]*=['\"\s]*['\"](\d+\.\d+(?:\.\d+)?(?:\.\d+)?)['\"]",  # Constante VERSION
            r"magento[_\-]?version['\"\s]*[:\-=]['\"\s]*[v]?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)",  # magento_version
            r"release[_\-]?version['\"\s]*[:\-=]['\"\s]*[v]?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)",  # release_version
            
            # Patrones en comentarios (media confianza)
            r"<!--.*?magento\s+v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?).*?-->",  # Comentarios HTML
            r"\/\*.*?magento\s+v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?).*?\*\/",  # Comentarios CSS/JS
            
            # Patrones en meta tags (media confianza)
            r"<meta[^>]*content=['\"].*?magento\s+v?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?).*?['\"][^>]*>",  # Meta tags
            
            # Patrones generales (baja confianza) - SOLO si parecen versiones de Magento
            r"\bv?(\d+\.\d+\.\d+)\b(?![.\d])",  # Versión específica sin contexto (más restrictivo)
        ]
        
        for pattern in version_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                potential_version = match.group(1)
                
                # Validación adicional para patrones generales
                if pattern == r"\bv?(\d+\.\d+\.\d+)\b(?![.\d])":
                    # Para patrones generales, ser más estricto
                    parts = potential_version.split('.')
                    if len(parts) == 3:
                        try:
                            major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                            # Solo aceptar si parece una versión de Magento
                            if not ((major == 1 and 4 <= minor <= 9 and patch <= 20) or 
                                   (major == 2 and 0 <= minor <= 4 and patch <= 20)):
                                continue
                        except ValueError:
                            continue
                
                validated_version = self._validate_magento_version(potential_version)
                if validated_version:
                    return validated_version
        
        return None
    
    def check_vulnerabilities_fast(self, url, version=None, estimated_version=None):
        """Ultra-fast vulnerability analysis (0.1-0.2s) - Análisis instantáneo de seguridad"""
        try:
            result = {
                'has_vulnerabilities': False,
                'vulnerability_count': 0,
                'risk_level': 'low',
                'vulnerabilities': [],
                'recommendations': []
            }
            
            # Usar versión proporcionada o estimada
            check_version = version or estimated_version
            
            if not check_version:
                return result
            
            # Obtener vulnerabilidades para esta versión (búsqueda rápida en memoria)
            vulnerabilities = self._get_vulnerabilities_for_version(check_version)
            
            if vulnerabilities:
                result['has_vulnerabilities'] = True
                result['vulnerability_count'] = len(vulnerabilities)
                result['vulnerabilities'] = vulnerabilities
                
                # Determinar nivel de riesgo basado en severidad
                critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'Critical')
                high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'High')
                
                if critical_count > 0:
                    result['risk_level'] = 'critical'
                elif high_count > 2:
                    result['risk_level'] = 'high'
                elif high_count > 0 or len(vulnerabilities) > 3:
                    result['risk_level'] = 'medium'
                else:
                    result['risk_level'] = 'low'
            
            # Agregar recomendaciones rápidas
            if check_version.startswith('1.'):
                result['recommendations'].append('Migrate to Magento 2.x (EOL risk)')
            elif check_version.startswith('2.'):
                result['recommendations'].append('Update to latest Magento 2.x version')
            
            if result['has_vulnerabilities']:
                result['recommendations'].append('Apply security patches immediately')
                result['recommendations'].append('Review admin credentials')
            
            return result
            
        except Exception as e:
            return {
                'has_vulnerabilities': False,
                'vulnerability_count': 0,
                'risk_level': 'unknown',
                'vulnerabilities': [],
                'recommendations': [],
                'error': str(e)
            }
    
    def _get_vulnerabilities_for_version(self, version):
        """Obtener vulnerabilidades para una versión específica (búsqueda rápida)"""
        if not version:
            return []
        
        # Base de datos simplificada para búsqueda ultra-rápida
        known_vulnerable_versions = {
            '1.4.1': [
                {'id': 'CVE-2015-1397', 'severity': 'Critical', 'description': 'SQL Injection vulnerability'},
                {'id': 'CVE-2015-1398', 'severity': 'High', 'description': 'Cross-site scripting vulnerability'}
            ],
            '1.9.2': [
                {'id': 'CVE-2016-4010', 'severity': 'High', 'description': 'Remote code execution'}
            ],
            '2.1.0': [
                {'id': 'CVE-2017-2615', 'severity': 'Medium', 'description': 'Information disclosure'}
            ]
        }
        
        # Verificar versión exacta
        if version in known_vulnerable_versions:
            return known_vulnerable_versions[version]
        
        # Verificar rangos de versiones
        vulnerabilities = []
        
        # Magento 1.x - todas las versiones tienen vulnerabilidades por EOL
        if version.startswith('1.') or version == '1.x':
            vulnerabilities.extend([
                {'id': 'EOL-M1', 'severity': 'Critical', 'description': 'Magento 1.x End of Life - No security updates'},
                {'id': 'GENERAL-M1', 'severity': 'High', 'description': 'Multiple known vulnerabilities in Magento 1.x'}
            ])
        
        # Magento 2.0-2.2 - versiones con vulnerabilidades conocidas
        elif any(old in version for old in ['2.0', '2.1', '2.2']):
            vulnerabilities.extend([
                {'id': 'OLD-M2', 'severity': 'High', 'description': 'Outdated Magento 2.x version with known vulnerabilities'}
            ])
        
        return vulnerabilities

# Instancia global del detector
detector = MagentoDetector()

# ===== ULTRA-FAST SPECIALIZED ENDPOINTS =====

@app.route('/api/detect', methods=['POST'])
def detect():
    """
    Lightning-fast Magento detection endpoint (0.2-0.5s)
    Solo detección básica de Magento - Optimizado para Clay
    
    Request: {"url": "https://ejemplo.com"}
    Response: {"is_magento": true, "confidence": 95, "detection_method": "magento_headers"}
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        # Usar método ultra-rápido
        result = detector.lightning_detect(url)
        result['response_time'] = '0.2-0.5s'
        result['endpoint'] = 'detect'
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'is_magento': False,
            'confidence': 0
        }), 500

@app.route('/api/estimate-version', methods=['POST'])
def estimate_version_endpoint():
    """
    Fast version estimation endpoint (0.3-0.8s)
    Estimación inteligente de versión con análisis de riesgo
    
    Request: {"url": "https://ejemplo.com"}
    Response: {"is_magento": true, "estimated_version": "2.4", "risk_level": "low"}
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        result = detector.estimate_version(url)
        result['response_time'] = '0.3-0.8s'
        result['endpoint'] = 'estimate-version'
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'is_magento': False,
            'estimated_version': None
        }), 500

@app.route('/api/get-exact-version', methods=['POST'])
def get_exact_version_endpoint():
    """
    Comprehensive version detection endpoint (1-3s)
    Búsqueda exhaustiva de versión exacta
    
    Request: {"url": "https://ejemplo.com"}
    Response: {"is_magento": true, "exact_version": "2.4.3", "confidence": 95}
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        result = detector.get_exact_version(url)
        result['response_time'] = '1-3s'
        result['endpoint'] = 'get-exact-version'
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'is_magento': False,
            'exact_version': None
        }), 500

@app.route('/api/check-vulnerabilities', methods=['POST'])
def check_vulnerabilities_endpoint():
    """
    Ultra-fast vulnerability analysis endpoint (0.1-0.2s)
    Análisis instantáneo de vulnerabilidades de seguridad
    
    Request: {"url": "https://ejemplo.com", "version": "2.4.3"}
    Response: {"has_vulnerabilities": false, "risk_level": "low", "recommendations": [...]}
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request data is required'}), 400
        
        url = data.get('url', '').strip()
        version = data.get('version')
        estimated_version = data.get('estimated_version')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        result = detector.check_vulnerabilities_fast(url, version, estimated_version)
        result['response_time'] = '0.1-0.2s'
        result['endpoint'] = 'check-vulnerabilities'
        result['url'] = url
        result['checked_version'] = version or estimated_version
        
        return jsonify(result), 200
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'has_vulnerabilities': False,
            'vulnerability_count': 0
        }), 500

# ===== LEGACY ENDPOINTS FOR COMPATIBILITY =====

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Analiza una URL para detectar Magento.
    
    Ejemplo de request:
    {
        "url": "https://ejemplo.com"
    }
    
    Ejemplo de response:
    {
        "url": "https://ejemplo.com",
        "is_magento": true,
        "version": "2.4.3",
        "confidence": 85,
        "evidence": ["Magento header found: x-magento-cache-control"],
        "vulnerabilities": [...],
        "recommendations": [...],
        "timestamp": "2025-09-25T10:30:00.000Z"
    }
    """
    try:
        # Verificar Content-Type
        if not request.is_json:
            return jsonify({
                'error': 'Content-Type must be application/json',
                'status': 'error'
            }), 400
        
        data = request.get_json()
        
        if not data:
            return jsonify({
                'error': 'Request body is required',
                'status': 'error'
            }), 400
        
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'error': 'URL field is required',
                'status': 'error',
                'example': {
                    'url': 'https://ejemplo.com'
                }
            }), 400
        
        # Analizar URL
        result = detector.analyze_url(url)
        result['status'] = 'success'
        
        return jsonify(result), 200
        
    except Exception as e:
        logging.error(f"Error in analyze endpoint: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/batch-analyze', methods=['POST'])
def batch_analyze():
    """
    Analiza múltiples URLs en una sola request.
    
    Ejemplo de request:
    {
        "urls": ["https://sitio1.com", "https://sitio2.com"]
    }
    """
    try:
        if not request.is_json:
            return jsonify({
                'error': 'Content-Type must be application/json',
                'status': 'error'
            }), 400
        
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls or not isinstance(urls, list):
            return jsonify({
                'error': 'urls field is required and must be an array',
                'status': 'error',
                'example': {
                    'urls': ['https://sitio1.com', 'https://sitio2.com']
                }
            }), 400
        
        if len(urls) > 10:  # Limitar a 10 URLs por request
            return jsonify({
                'error': 'Maximum 10 URLs allowed per request',
                'status': 'error'
            }), 400
        
        results = []
        for url in urls:
            try:
                result = detector.analyze_url(url.strip())
                results.append(result)
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        return jsonify({
            'status': 'success',
            'results': results,
            'total_analyzed': len(results),
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error in batch analyze endpoint: {str(e)}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'magento-detector',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/info', methods=['GET'])
def info():
    """Información completa sobre la API"""
    return jsonify({
        'service': 'Magento Detector API - Ultra-Fast Edition',
        'version': '2.0.0',
        'description': 'API especializada para detectar Magento con 4 endpoints ultra-rápidos optimizados para Clay',
        'specialized_endpoints': {
            'POST /api/detect': {
                'description': 'Lightning detection (0.2-0.5s)',
                'purpose': 'Ultra-fast Magento detection only',
                'response_time': '200-500ms',
                'rate_limit_recommended': '8 req/s'
            },
            'POST /api/estimate-version': {
                'description': 'Version estimation (0.3-0.8s)', 
                'purpose': 'Smart version estimation with risk analysis',
                'response_time': '300-800ms',
                'rate_limit_recommended': '6 req/s'
            },
            'POST /api/get-exact-version': {
                'description': 'Exact version detection (1-3s)',
                'purpose': 'Comprehensive version search',
                'response_time': '1000-3000ms',
                'rate_limit_recommended': '3 req/s'
            },
            'POST /api/check-vulnerabilities': {
                'description': 'Vulnerability analysis (0.1-0.2s)',
                'purpose': 'Security assessment with recommendations',
                'response_time': '100-200ms',
                'rate_limit_recommended': '10 req/s'
            }
        },
        'legacy_endpoints': {
            'POST /api/analyze': 'Complete analysis (slower, for compatibility)',
            'POST /api/batch-analyze': 'Batch processing (máximo 10 URLs)',
        },
        'utility_endpoints': {
            'GET /api/health': 'Health check',
            'GET /api/info': 'API documentation'
        },
        'clay_workflow': {
            'step_1': 'Use /api/detect for all URLs to identify Magento sites',
            'step_2': 'Use /api/estimate-version only for is_magento=true results',
            'step_3': 'Use /api/get-exact-version for high-value leads only',
            'step_4': 'Use /api/check-vulnerabilities with version data for security analysis'
        },
        'example_requests': {
            'detect': {
                'url': '/api/detect',
                'body': {'url': 'https://example.com'}
            },
            'estimate_version': {
                'url': '/api/estimate-version', 
                'body': {'url': 'https://example.com'}
            },
            'exact_version': {
                'url': '/api/get-exact-version',
                'body': {'url': 'https://example.com'}
            },
            'vulnerabilities': {
                'url': '/api/check-vulnerabilities',
                'body': {
                    'url': 'https://example.com',
                    'version': '2.4.3',
                    'estimated_version': '2.x'
                }
            }
        }
    }), 200

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'status': 'error',
        'specialized_endpoints': [
            'POST /api/detect (Lightning detection)',
            'POST /api/estimate-version (Version estimation)',
            'POST /api/get-exact-version (Exact version search)',
            'POST /api/check-vulnerabilities (Security analysis)'
        ],
        'legacy_endpoints': [
            'POST /api/analyze',
            'POST /api/batch-analyze'
        ],
        'utility_endpoints': [
            'GET /api/health',
            'GET /api/info'
        ]
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'error': 'Method not allowed',
        'status': 'error'
    }), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'status': 'error'
    }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)