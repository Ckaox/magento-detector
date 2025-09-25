#!/bin/bash

# Script de prueba para los 4 endpoints especializados ultra-rápidos
# Magento Detector API - Ultra-Fast Edition v2.0.0

echo "=========================================="
echo "MAGENTO DETECTOR API - ULTRA-FAST ENDPOINTS"
echo "=========================================="
echo ""

# URL base del API
API_BASE="http://localhost:5000"

# URLs de prueba
TEST_URLS=(
    "https://example.com"
    "https://github.com"
)

echo "🚀 Probando los 4 endpoints especializados:"
echo ""

for url in "${TEST_URLS[@]}"; do
    echo "🔍 Analizando: $url"
    echo "----------------------------------------"
    
    # 1. Lightning Detection (0.2-0.5s)
    echo "⚡ 1. Lightning Detection (0.2-0.5s):"
    start_time=$(date +%s%N)
    detect_result=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"url\":\"$url\"}" "$API_BASE/api/detect")
    end_time=$(date +%s%N)
    duration=$((($end_time - $start_time) / 1000000))
    echo "   Response: $detect_result"
    echo "   Actual time: ${duration}ms"
    
    # Extraer si es Magento para decidir si continuar
    is_magento=$(echo $detect_result | grep -o '"is_magento":[^,]*' | cut -d':' -f2)
    
    if [[ "$is_magento" == "true" ]]; then
        echo ""
        
        # 2. Version Estimation (0.3-0.8s) - Solo si es Magento
        echo "🔢 2. Version Estimation (0.3-0.8s):"
        start_time=$(date +%s%N)
        version_result=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"url\":\"$url\"}" "$API_BASE/api/estimate-version")
        end_time=$(date +%s%N)
        duration=$((($end_time - $start_time) / 1000000))
        echo "   Response: $version_result"
        echo "   Actual time: ${duration}ms"
        echo ""
        
        # 3. Exact Version (1-3s) - Solo para leads importantes
        echo "🎯 3. Exact Version Detection (1-3s):"
        start_time=$(date +%s%N)
        exact_result=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"url\":\"$url\"}" "$API_BASE/api/get-exact-version")
        end_time=$(date +%s%N)
        duration=$((($end_time - $start_time) / 1000000))
        echo "   Response: $exact_result"
        echo "   Actual time: ${duration}ms"
        echo ""
        
        # 4. Vulnerability Check (0.1-0.2s)
        echo "🛡️  4. Vulnerability Analysis (0.1-0.2s):"
        start_time=$(date +%s%N)
        vuln_result=$(curl -s -X POST -H "Content-Type: application/json" -d "{\"url\":\"$url\",\"estimated_version\":\"2.x\"}" "$API_BASE/api/check-vulnerabilities")
        end_time=$(date +%s%N)
        duration=$((($end_time - $start_time) / 1000000))
        echo "   Response: $vuln_result"
        echo "   Actual time: ${duration}ms"
    else
        echo "   ❌ No es Magento - Saltando análisis adicionales (optimización Clay)"
    fi
    
    echo ""
    echo "=========================================="
    echo ""
done

echo "✅ Prueba completada!"
echo ""
echo "🔥 WORKFLOW RECOMENDADO PARA CLAY:"
echo "1. Usa /api/detect para TODAS las URLs (0.2-0.5s)"
echo "2. Usa /api/estimate-version solo para is_magento=true (0.3-0.8s)"
echo "3. Usa /api/get-exact-version para leads de alto valor (1-3s)"
echo "4. Usa /api/check-vulnerabilities con datos de versión (0.1-0.2s)"
echo ""
echo "🚀 Rate Limits Recomendados:"
echo "   • /api/detect: 8 req/s"
echo "   • /api/estimate-version: 6 req/s"  
echo "   • /api/get-exact-version: 3 req/s"
echo "   • /api/check-vulnerabilities: 10 req/s"