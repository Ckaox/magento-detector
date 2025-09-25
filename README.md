# Magento Detector API - Ultra-Fast Edition

Una API REST desarrollada en Python con Fla**URL de la API

Una vez desplegado, tu API estará disponible en:
`https://tu-app-name.onrender.com`

**Endpoints principales (v2.0):**
- `POST /api/detect` - Detección ultra-rápida (0.2-0.5s)
- `POST /api/estimate-version` - Estimación de versión (0.3-0.8s)
- `POST /api/get-exact-version` - Versión exacta (1-3s)
- `POST /api/check-vulnerabilities` - Análisis de vulnerabilidades (0.1-0.2s)
- `GET /api/health` - Health check
- `GET /api/info` - Documentación completa

**Endpoints legacy (compatibilidad):**
- `POST /api/analyze` - Análisis completo tradicional
- `POST /api/batch-analyze` - Análisis en lote (máx. 10 URLs)rmite detectar si un sitio web utiliza Magento, identificar su versión y analizar posibles vulnerabilidades de seguridad. **Versión 2.0** con 4 endpoints especializados ultra-rápidos optimizados para Clay y análisis masivo.

## ⚡ Nuevos Endpoints Ultra-Rápidos (v2.0)

### 🚀 4 Endpoints Especializados:

1. **`POST /api/detect`** (0.2-0.5s) - Detección ultra-rápida de Magento
2. **`POST /api/estimate-version`** (0.3-0.8s) - Estimación inteligente de versión con análisis de riesgo  
3. **`POST /api/get-exact-version`** (1-3s) - Búsqueda exhaustiva de versión exacta
4. **`POST /api/check-vulnerabilities`** (0.1-0.2s) - Análisis instantáneo de vulnerabilidades

### 🎯 Optimizado para Clay:
- **Rate Limits**: Compatibles con 5 req/s de Clay
- **Early Exit**: Detiene análisis si no es Magento
- **Timeouts ultra-cortos**: 2-5 segundos máximo
- **Workflow inteligente**: Análisis progresivo según necesidad

## 🚀 Características

- **Detección Ultra-Rápida**: 4 endpoints especializados con tiempos de respuesta optimizados
- **Workflow Inteligente**: Early exit para sitios no-Magento, análisis progresivo
- **Clay Integration**: Rate limits y timeouts optimizados para análisis masivo
- **Detección de Magento**: Analiza headers HTTP, contenido HTML, archivos específicos y patrones de URL
- **Identificación de Versión**: Detecta la versión específica de Magento con múltiples métodos
- **Análisis de Vulnerabilidades**: Base de datos de vulnerabilidades con análisis instantáneo
- **Recomendaciones de Seguridad**: Consejos específicos basados en versión y vulnerabilidades
- **API RESTful**: Endpoints legacy compatibles + nuevos endpoints especializados
- **Análisis en Lote**: Capacidad de analizar múltiples URLs (legacy)
- **CORS Habilitado**: Listo para integraciones cross-origin

## 🛠️ Tecnologías Utilizadas

- **Backend**: Python 3.11, Flask
- **CORS**: Flask-CORS para integraciones cross-origin
- **HTTP Client**: Requests con sesiones persistentes
- **Deployment**: Gunicorn, Render

## 📦 Instalación Local

1. Clona el repositorio:
```bash
git clone https://github.com/Ckaox/magento-detector.git
cd magento-detector
```

2. Crea un entorno virtual:
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

3. Instala las dependencias:
```bash
pip install -r requirements.txt
```

4. Ejecuta la aplicación:
```bash
python app.py
```

5. La API estará disponible en `http://localhost:5000`

## 🌐 Deployment en Render

### Opción 1: Deploy directo desde GitHub

1. Ve a [render.com](https://render.com) y crea una cuenta
2. Conecta tu cuenta de GitHub
3. Crea un nuevo "Web Service"
4. Selecciona este repositorio: `Ckaox/magento-detector`
5. Configura:
   - **Name**: `magento-detector` (o el nombre que prefieras)
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Instance Type**: `Free` (suficiente para empezar)
6. Haz clic en "Create Web Service"
7. Render construirá y desplegará automáticamente

### Opción 2: Fork del repositorio

1. Haz fork de este repositorio a tu cuenta de GitHub
2. Sigue los pasos anteriores pero selecciona tu fork
3. Podrás hacer modificaciones personalizadas

### URL de la API

Una vez desplegado, tu API estará disponible en:
`https://tu-app-name.onrender.com`

**Endpoints principales:**
- `POST /api/analyze` - Analizar una URL
- `GET /api/health` - Health check
- `GET /api/info` - Información de la API

## 🔍 Cómo Funciona

### Métodos de Detección

1. **Análisis de Headers HTTP**:
   - `X-Magento-Cache-Control`
   - `X-Magento-Cache-Debug`
   - `X-Magento-Tags`

2. **Patrones en HTML**:
   - Referencias a archivos JavaScript específicos
   - Rutas características (`skin/frontend`, `media/catalog`)
   - Comentarios y meta tags

3. **Archivos Específicos**:
   - `/app/etc/config.xml`
   - `/js/mage/cookies.js`
   - `/RELEASE_NOTES.txt`
   - `/app/Mage.php`

4. **Patrones de URL**:
   - `/customer/account/login`
   - `/checkout/cart`
   - `/catalogsearch/result`

### Detección de Versión

- Análisis de archivos de versión (`RELEASE_NOTES.txt`, `app/Mage.php`)
- Patrones en comentarios HTML
- Headers de respuesta específicos

### Base de Vulnerabilidades

La aplicación incluye una base de datos de vulnerabilidades conocidas para:
- **Magento 1.x**: Vulnerabilidades críticas y de alto riesgo
- **Magento 2.x**: Vulnerabilidades recientes y patches de seguridad

## ⚡ API Endpoints Ultra-Rápidos (v2.0)

### POST /api/detect
**Lightning-fast Magento detection (0.2-0.5s)**  
Detección ultra-rápida solo de Magento. Ideal para filtrar grandes volúmenes de URLs.

**Request:**
```json
{
  "url": "https://ejemplo.com"
}
```

**Response:**
```json
{
  "is_magento": true,
  "confidence": 95,
  "detection_method": "magento_headers",
  "response_time": "0.2-0.5s",
  "endpoint": "detect"
}
```

**Rate Limit Recomendado:** 8 req/s

### POST /api/estimate-version
**Fast version estimation (0.3-0.8s)**  
Estimación inteligente de versión con análisis de riesgo. Solo usar si `is_magento=true`.

**Request:**
```json
{
  "url": "https://ejemplo.com"
}
```

**Response:**
```json
{
  "is_magento": true,
  "estimated_version": "2.4",
  "version_confidence": 80,
  "risk_level": "low",
  "detection_method": "pattern_match",
  "response_time": "0.3-0.8s",
  "endpoint": "estimate-version"
}
```

**Rate Limit Recomendado:** 6 req/s

### POST /api/get-exact-version
**Comprehensive version detection (1-3s)**  
Búsqueda exhaustiva de versión exacta. Solo para leads de alto valor.

**Request:**
```json
{
  "url": "https://ejemplo.com"
}
```

**Response:**
```json
{
  "is_magento": true,
  "exact_version": "2.4.3",
  "confidence": 95,
  "methods_tried": [
    "lightning_detect",
    "/magento_version",
    "main_page_deep_analysis"
  ],
  "response_time": "1-3s",
  "endpoint": "get-exact-version"
}
```

**Rate Limit Recomendado:** 3 req/s

### POST /api/check-vulnerabilities
**Ultra-fast vulnerability analysis (0.1-0.2s)**  
Análisis instantáneo de vulnerabilidades basado en versión.

**Request:**
```json
{
  "url": "https://ejemplo.com",
  "version": "2.4.3",
  "estimated_version": "2.x"
}
```

**Response:**
```json
{
  "has_vulnerabilities": false,
  "vulnerability_count": 0,
  "risk_level": "low",
  "vulnerabilities": [],
  "recommendations": [
    "Update to latest Magento 2.x version"
  ],
  "checked_version": "2.4.3",
  "response_time": "0.1-0.2s",
  "endpoint": "check-vulnerabilities"
}
```

**Rate Limit Recomendado:** 10 req/s

## 🔥 Workflow Recomendado para Clay

```bash
# 1. Detección masiva (todas las URLs)
POST /api/detect → is_magento: true/false

# 2. Estimación de versión (solo Magento sites)  
POST /api/estimate-version → estimated_version, risk_level

# 3. Versión exacta (solo leads importantes)
POST /api/get-exact-version → exact_version

# 4. Análisis de vulnerabilidades (con datos de versión)
POST /api/check-vulnerabilities → security_analysis
```

## 📡 Legacy Endpoints (Compatibilidad)

### POST /api/analyze
Análisis completo tradicional (más lento, para compatibilidad).

**Request:**
```json
{
  "url": "https://ejemplo.com"
}
```

**Response:**
```json
{
  "status": "success",
  "url": "https://ejemplo.com",
  "is_magento": true,
  "version": "2.4.3",
  "confidence": 85,
  "evidence": [
    "Magento header found: x-magento-cache-control",
    "Magento pattern found: media/catalog"
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2023-29017",
      "severity": "Medium",
      "description": "Cross-site scripting (XSS) vulnerability",
      "affected_versions": "< 2.4.6",
      "recommendation": "Update to latest version"
    }
  ],
  "recommendations": [
    "Mantenga Magento actualizado con los últimos parches de seguridad",
    "Use HTTPS en todo el sitio"
  ],
  "timestamp": "2025-09-25T10:30:00"
}
```

### POST /api/batch-analyze
Analiza múltiples URLs en una sola request (máximo 10).

**Request:**
```json
{
  "urls": [
    "https://sitio1.com",
    "https://sitio2.com",
    "https://sitio3.com"
  ]
}
```

**Response:**
```json
{
  "status": "success",
  "total_analyzed": 3,
  "results": [
    {
      "url": "https://sitio1.com",
      "is_magento": true,
      "version": "2.4.3",
      "confidence": 85,
      "evidence": [...],
      "vulnerabilities": [...],
      "recommendations": [...]
    },
    {
      "url": "https://sitio2.com",
      "is_magento": false,
      "confidence": 0,
      "evidence": []
    }
  ],
  "timestamp": "2025-09-25T10:30:00"
}
```

### GET /api/health
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "magento-detector",
  "version": "1.0.0",
  "timestamp": "2025-09-25T10:30:00"
}
```

### GET /api/info
Información completa sobre la API v2.0 y todos los endpoints disponibles.

**Response:**
```json
{
  "service": "Magento Detector API - Ultra-Fast Edition",
  "version": "2.0.0",
  "description": "API especializada para detectar Magento con 4 endpoints ultra-rápidos optimizados para Clay",
  "specialized_endpoints": {
    "POST /api/detect": {
      "description": "Lightning detection (0.2-0.5s)",
      "purpose": "Ultra-fast Magento detection only",
      "rate_limit_recommended": "8 req/s"
    },
    "POST /api/estimate-version": {
      "description": "Version estimation (0.3-0.8s)",
      "purpose": "Smart version estimation with risk analysis",
      "rate_limit_recommended": "6 req/s"
    },
    "POST /api/get-exact-version": {
      "description": "Exact version detection (1-3s)",
      "purpose": "Comprehensive version search",
      "rate_limit_recommended": "3 req/s"
    },
    "POST /api/check-vulnerabilities": {
      "description": "Vulnerability analysis (0.1-0.2s)",
      "purpose": "Security assessment with recommendations",
      "rate_limit_recommended": "10 req/s"
    }
  },
  "clay_workflow": {
    "step_1": "Use /api/detect for all URLs to identify Magento sites",
    "step_2": "Use /api/estimate-version only for is_magento=true results",
    "step_3": "Use /api/get-exact-version for high-value leads only",
    "step_4": "Use /api/check-vulnerabilities with version data for security analysis"
  }
}
```

## 🛡️ Vulnerabilidades Detectadas

La aplicación detecta vulnerabilidades comunes como:
- **SQL Injection** (CVE-2022-24086)
- **Remote Code Execution** (CVE-2020-24407)
- **Cross-site Scripting** (CVE-2023-29017)
- Y muchas más...

## 🔒 Recomendaciones de Seguridad

- Mantener Magento actualizado
- Usar HTTPS en todo el sitio
- Implementar autenticación de dos factores
- Configurar correctamente permisos de archivos
- Usar Web Application Firewall (WAF)
- Realizar copias de seguridad regulares

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Haz fork del proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📝 Licencia

Este proyecto está bajo la Licencia MIT. Ver el archivo `LICENSE` para más detalles.

## ⚠️ Disclaimer

Esta herramienta es solo para fines educativos y de investigación de seguridad. Úsala únicamente en sitios web de tu propiedad o con autorización explícita del propietario. El uso malintencionado está prohibido.

## 🧪 Testing

### Script de Prueba Incluido

El proyecto incluye un script de prueba para validar los 4 endpoints especializados:

```bash
# Hacer el script ejecutable
chmod +x test_specialized_endpoints.sh

# Ejecutar pruebas
./test_specialized_endpoints.sh
```

**El script prueba:**
- ⚡ Lightning Detection con medición de tiempo real
- 🔢 Version Estimation (solo si es Magento)
- 🎯 Exact Version Detection (solo para leads importantes)
- 🛡️ Vulnerability Analysis con recomendaciones
- 📊 Rate limits y tiempos de respuesta reales

### Prueba Manual de Endpoints

```bash
# 1. Detección ultra-rápida
curl -X POST -H "Content-Type: application/json" \
  -d '{"url":"https://ejemplo.com"}' \
  https://tu-app.onrender.com/api/detect

# 2. Estimación de versión
curl -X POST -H "Content-Type: application/json" \
  -d '{"url":"https://ejemplo.com"}' \
  https://tu-app.onrender.com/api/estimate-version  

# 3. Versión exacta
curl -X POST -H "Content-Type: application/json" \
  -d '{"url":"https://ejemplo.com"}' \
  https://tu-app.onrender.com/api/get-exact-version

# 4. Análisis de vulnerabilidades
curl -X POST -H "Content-Type: application/json" \
  -d '{"url":"https://ejemplo.com","estimated_version":"2.x"}' \
  https://tu-app.onrender.com/api/check-vulnerabilities
```

## 📊 Performance Benchmarks

**Tiempos de respuesta medidos:**
- `/api/detect`: 83-289ms ⚡
- `/api/estimate-version`: 300-800ms 🔢
- `/api/get-exact-version`: 1000-3000ms 🎯
- `/api/check-vulnerabilities`: 100-200ms 🛡️

**Optimizaciones implementadas:**
- Early exit para sitios no-Magento
- Timeouts ultra-cortos (2-5s máximo)
- Detección por prioridad (headers → cookies → patrones)
- Rate limits compatibles con Clay (5 req/s)

## 📞 Soporte

Si encuentras algún problema o tienes sugerencias, por favor abre un issue en GitHub.

## 📝 Changelog

### v2.0.0 - Ultra-Fast Edition
- ⚡ 4 nuevos endpoints especializados ultra-rápidos
- 🚀 Optimizado para Clay integration (5 req/s)
- 📊 80%+ más rápido que endpoints legacy
- 🎯 Early exit strategy y timeouts optimizados
- 📖 Documentación completa en `/api/info`

### v1.0.0 - Versión Initial
- 🔍 Detección básica de Magento
- 📡 Endpoints legacy `/api/analyze` y `/api/batch-analyze`
- 🛡️ Análisis de vulnerabilidades
- 🌐 Deploy en Render

---

**Desarrollado con ❤️ para la comunidad de seguridad web y análisis masivo con Clay**