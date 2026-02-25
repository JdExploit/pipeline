#!/usr/bin/env python3
"""
APLICACIÓN DEMOSTRATIVA PARA PRÁCTICA DE SEGURIDAD
Esta aplicación contiene vulnerabilidades INTENCIONALES para demostrar
las capacidades de Bandit y TruffleHog en el pipeline de CI/CD

Autor: JDEXPLOIT
Fecha: 2026
Versión: 1.0
"""

import os
import subprocess
import hashlib
import pickle
import sqlite3
import requests
import base64
import json
from datetime import datetime

# ============================================================
# SECCIÓN 1: SECRETOS EXPUESTOS (PARA TRUFFLEHOG)
# ============================================================
# ¡ADVERTENCIA! Estos secretos están intencionalmente expuestos
# para demostrar la detección de TruffleHog

# API Key de AWS (formato real para detección)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Token de GitHub
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"

# Clave de API de Stripe (formato de prueba)
STRIPE_API_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc"

# Contraseña hardcodeada
DATABASE_PASSWORD = "SuperSecretPassword2024!"

# ============================================================
# SECCIÓN 2: CLASE PRINCIPAL CON VULNERABILIDADES
# ============================================================

class PaymentProcessor:
    """
    Procesador de pagos - VERSIÓN VULNERABLE
    Esta clase contiene múltiples vulnerabilidades que serán
    detectadas por Bandit durante el análisis SAST.
    """
    
    def __init__(self):
        self.name = "PaymentProcessor"
        self.debug_mode = True
        self.api_endpoint = "https://api.ejemplo.com/v1"
        
        # Credenciales hardcodeadas (B105 - hardcoded_password_string)
        self.api_username = "admin"
        self.api_password = "admin123"  # Bandit detectará esto
        
    def execute_system_command(self, user_command):
        """
        [VULNERABILIDAD B607]
        Ejecuta comandos del sistema - PELIGROSO
        """
        # Uso peligroso de os.system() con entrada del usuario
        # Bandit detectará esto como B605:start_process_with_partial_path
        os.system(f"echo {user_command} > /tmp/output.txt")
        
    def unsafe_subprocess_call(self, user_input):
        """
        [VULNERABILIDAD B602]
        Uso inseguro de subprocess con shell=True
        """
        # shell=True permite inyección de comandos
        # Ejemplo: user_input = "; cat /etc/passwd"
        result = subprocess.Popen(
            f"grep {user_input} /var/log/system.log",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        output, error = result.communicate()
        return output
    
    def weak_encryption(self, data):
        """
        [VULNERABILIDAD B303]
        Uso de algoritmos criptográficos débiles
        """
        # MD5 está considerado inseguro desde 2012
        # Bandit lo marca como blacklist
        hash_md5 = hashlib.md5(data.encode()).hexdigest()
        
        # SHA1 también está comprometido
        hash_sha1 = hashlib.sha1(data.encode()).hexdigest()
        
        return {"md5": hash_md5, "sha1": hash_sha1}
    
    def insecure_deserialization(self, base64_data):
        """
        [VULNERABILIDAD B301]
        Deserialización insegura con pickle
        """
        # Pickle puede ejecutar código arbitrario al deserializar
        # Esto es extremadamente peligroso con datos de usuario
        decoded_data = base64.b64decode(base64_data)
        obj = pickle.loads(decoded_data)  # Ejecución de código arbitrario
        return obj
    
    def sql_injection_vulnerable(self, user_id):
        """
        [VULNERABILIDAD B608]
        Inyección SQL por concatenación de strings
        """
        # NUNCA concatenar strings en SQL
        # Esto permite inyección SQL: user_id = "1; DROP TABLE users;"
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # VULNERABLE: Concatenación directa
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
        
        result = cursor.fetchall()
        conn.close()
        return result
    
    def unsafe_yaml_load(self, yaml_data):
        """
        [VULNERABILIDAD B506]
        Carga insegura de YAML
        """
        import yaml
        # yaml.load() es inseguro, usar yaml.safe_load()
        data = yaml.load(yaml_data)  # Puede ejecutar código
        return data
    
    def request_without_verify(self, url):
        """
        [VULNERABILIDAD B501]
        Peticiones sin verificación SSL
        """
        # verify=False desactiva la validación del certificado SSL
        # Esto permite ataques Man-in-the-Middle
        response = requests.get(url, verify=False)
        return response.text
    
    def hardcoded_credentials_function(self):
        """
        [VULNERABILIDAD B105]
        Múltiples credenciales hardcodeadas
        """
        # Bandit detectará todas estas como hardcoded passwords
        db_user = "root"
        db_pass = "toor"  # Password hardcodeada
        api_key = "12345-abcdef-67890"  # API key hardcodeada
        jwt_secret = "supersecretjwtkey123"  # Secreto JWT hardcodeado
        
        return {"user": db_user, "pass": db_pass}
    
    def temporary_file_insecurity(self):
        """
        [VULNERABILIDAD B108]
        Uso inseguro de /tmp
        """
        # /tmp es accesible por todos los usuarios del sistema
        temp_file = "/tmp/sensitive_data.txt"
        
        with open(temp_file, 'w') as f:
            f.write("Información confidencial aquí")
        
        # El archivo es legible por cualquier proceso
        return temp_file
    
    # ============================================================
    # SECCIÓN 3: FUNCIONES SEGURAS (PARA DEMOSTRAR # nosec)
    # ============================================================
    
    def legacy_compatibility_function(self):
        """
        Esta función usa eval() pero es necesaria para compatibilidad
        con sistemas legacy. Se marca con # nosec para que Bandit la ignore.
        """
        # Validamos que la entrada es segura (solo números)
        expression = "2 + 2"
        
        # nosec - Excluimos esta línea del análisis de Bandit
        result = eval(expression)  # nosec B307
        
        return result
    
    def required_system_call(self):
        """
        Llamada al sistema necesaria para reiniciar servicio
        La validación de entrada se hace en otro lugar
        """
        # nosec - Esta línea es necesaria para el funcionamiento
        os.system("systemctl restart apache2")  # nosec
        
        return True

# ============================================================
# SECCIÓN 4: PUNTO DE ENTRADA PRINCIPAL
# ============================================================

def main():
    """Función principal de la aplicación"""
    
    print("=" * 60)
    print("APLICACIÓN VULNERABLE - PRÁCTICA DE SEGURIDAD")
    print("=" * 60)
    print("\n[!] Esta aplicación contiene vulnerabilidades intencionales")
    print("[!] Solo para fines educativos\n")
    
    # Crear instancia del procesador
    processor = PaymentProcessor()
    
    # Ejecutar algunas funciones vulnerables
    print("[1] Probando comando del sistema...")
    processor.execute_system_command("test")
    
    print("[2] Probando hash débil...")
    hash_result = processor.weak_encryption("datos_secretos")
    print(f"    MD5: {hash_result['md5'][:20]}...")
    
    print("[3] Probando credenciales hardcodeadas...")
    creds = processor.hardcoded_credentials_function()
    print(f"    Usuario: {creds['user']}")
    
    print("\n" + "=" * 60)
    print("APLICACIÓN INICIADA CORRECTAMENTE")
    print("=" * 60)

if __name__ == "__main__":
    main()
