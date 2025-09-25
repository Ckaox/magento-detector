# Magento Detector API

Una API REST desarrollada en Python con Flask que permite detectar si un sitio web utiliza Magento, identificar su versión y analizar posibles vulnerabilidades de seguridad. Diseñada para integrarse con Clay y otros servicios externos.

## 🚀 Características

- **Detección de Magento**: Analiza headers HTTP, contenido HTML, archivos específicos y patrones de URL
- **Identificación de Versión**: Detecta la versión específica de Magento cuando es posible
- **Análisis de Vulnerabilidades**: Identifica vulnerabilidades conocidas basadas en la versión detectada
- **Recomendaciones de Seguridad**: Proporciona consejos específicos para mejorar la seguridad
- **API RESTful**: Endpoints optimizados para integraciones con Clay y otros servicios
- **Análisis en Lote**: Capacidad de analizar múltiples URLs en una sola request
- **CORS Habilitado**: Listo para integraciones desde navegadores

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

## 📡 API Endpoints

### POST /api/analyze
Analiza una URL individual para detectar Magento.

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
Información sobre la API y endpoints disponibles.

**Response:**
```json
{
  "service": "Magento Detector API",
  "version": "1.0.0",
  "description": "API para detectar instalaciones de Magento y analizar vulnerabilidades",
  "endpoints": {
    "POST /api/analyze": "Analiza una URL individual",
    "POST /api/batch-analyze": "Analiza múltiples URLs (máximo 10)",
    "GET /api/health": "Health check",
    "GET /api/info": "Información de la API"
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

## 📞 Soporte

Si encuentras algún problema o tienes sugerencias, por favor abre un issue en GitHub.

---

**Desarrollado con ❤️ para la comunidad de seguridad web**