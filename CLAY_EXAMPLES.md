# 🔗 Integración con Clay

Esta API está optimizada para integrarse perfectamente con Clay. Una vez desplegada en Render, podrás usar estos ejemplos:

## 🚀 Configuración Rápida

**URL de tu API en Render:** `https://tu-app-name.onrender.com`

### 1. Análisis de URL individual

```javascript
// Reemplaza 'tu-app-name' con el nombre real de tu app en Render
const API_URL = 'https://tu-app-name.onrender.com';

const response = await fetch(`${API_URL}/api/analyze`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    url: 'https://sitio-a-analizar.com'
  })
});

const data = await response.json();
console.log(data);
```

### 2. Análisis en lote (múltiples URLs)

```javascript
const response = await fetch('https://tu-app.onrender.com/api/batch-analyze', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    urls: [
      'https://sitio1.com',
      'https://sitio2.com',
      'https://sitio3.com'
    ]
  })
});

const data = await response.json();
// data.results contendrá los resultados para cada URL
```

### 3. Manejo de respuestas en Clay

```javascript
// Función para procesar la respuesta
function procesarResultadoMagento(resultado) {
  if (resultado.status === 'success') {
    if (resultado.is_magento) {
      console.log(`✅ Magento detectado en ${resultado.url}`);
      console.log(`Versión: ${resultado.version || 'No detectada'}`);
      console.log(`Confianza: ${resultado.confidence}%`);
      
      if (resultado.vulnerabilities && resultado.vulnerabilities.length > 0) {
        console.log(`⚠️ ${resultado.vulnerabilities.length} vulnerabilidades encontradas`);
        resultado.vulnerabilities.forEach(vuln => {
          console.log(`- ${vuln.id}: ${vuln.severity} - ${vuln.description}`);
        });
      }
    } else {
      console.log(`❌ Magento no detectado en ${resultado.url}`);
    }
  } else {
    console.log(`❌ Error: ${resultado.error}`);
  }
}
```

### 4. Integración con workflows de Clay

```javascript
// Ejemplo de función para usar en Clay
async function analizarMagento(url) {
  try {
    const response = await fetch('https://tu-app.onrender.com/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url })
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const data = await response.json();
    
    // Retornar datos estructurados para Clay
    return {
      es_magento: data.is_magento,
      version: data.version,
      confianza: data.confidence,
      vulnerabilidades_count: data.vulnerabilities ? data.vulnerabilities.length : 0,
      severidad_maxima: data.vulnerabilities && data.vulnerabilities.length > 0 
        ? data.vulnerabilities.reduce((max, v) => {
            const severities = { 'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1 };
            return (severities[v.severity] || 0) > (severities[max] || 0) ? v.severity : max;
          }, 'Low')
        : null,
      recomendaciones_count: data.recommendations ? data.recommendations.length : 0
    };
    
  } catch (error) {
    console.error('Error analizando Magento:', error);
    return {
      error: error.message,
      es_magento: false,
      confianza: 0
    };
  }
}
```

### 5. Campos útiles para extraer en Clay

Cuando uses la API, estos son los campos más útiles para tus análisis:

- `is_magento` (boolean): Si el sitio usa Magento
- `version` (string): Versión detectada
- `confidence` (number): Porcentaje de confianza (0-100)
- `vulnerabilities.length` (number): Cantidad de vulnerabilidades
- `vulnerabilities[].severity` (string): Severidad máxima encontrada
- `evidence.length` (number): Cantidad de evidencia encontrada

### 6. Manejo de errores

```javascript
// Ejemplo robusto con manejo de errores
async function analizarMagentoSeguro(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout
    
    const response = await fetch('https://tu-app.onrender.com/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url: url }),
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    const data = await response.json();
    
    if (data.status === 'error') {
      return { error: data.error, success: false };
    }
    
    return { ...data, success: true };
    
  } catch (error) {
    if (error.name === 'AbortError') {
      return { error: 'Timeout: Análisis tomó más de 30 segundos', success: false };
    }
    return { error: error.message, success: false };
  }
}
```

## URLs de ejemplo para probar

- **Magento 2.x**: https://magento.com
- **Magento 1.x**: Sitios más antiguos (difíciles de encontrar públicamente)
- **No Magento**: https://wordpress.com, https://shopify.com

## ⚡ Optimizaciones para Clay

### Campos más útiles para extraer:
```javascript
// Estructura de respuesta optimizada para Clay
{
  "is_magento": true,           // Boolean principal
  "version": "2.4",             // String de versión
  "confidence": 85,             // Número 0-100
  "vulnerabilities_count": 1,   // Cantidad de vulnerabilidades
  "max_severity": "Medium",     // Severidad máxima encontrada
  "evidence_count": 8           // Cantidad de evidencias
}
```

### Función optimizada para Clay:
```javascript
async function detectarMagento(url) {
  const response = await fetch('https://tu-app-name.onrender.com/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });
  
  const data = await response.json();
  
  return {
    es_magento: data.is_magento,
    version: data.version || 'N/A',
    confianza: data.confidence,
    vulnerabilidades: data.vulnerabilities?.length || 0,
    riesgo: data.vulnerabilities?.length > 0 ? 'Alto' : 'Bajo'
  };
}
```

## 🚨 Limitaciones

- Máximo 10 URLs por request en `/api/batch-analyze`
- Timeout de 30 segundos recomendado por request
- Algunos sitios con Cloudflare pueden ser más lentos
- La detección de versión exacta no siempre es posible
- Apps gratuitas de Render pueden tener cold start (~30s)