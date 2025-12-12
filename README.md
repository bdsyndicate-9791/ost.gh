# OPHELIA Stress Testing Tool (OST)

La herramienta de pruebas de estrés para aplicaciones OPHELIA es una utilidad de línea de comandos diseñada para probar la resistencia, rendimiento y seguridad de aplicaciones web bajo diferentes condiciones de carga y tipos de solicitudes.

## Características

- Pruebas de estrés concurrentes con múltiples hilos
- Soporte para diferentes tipos de pruebas de ataque:
  - `standard`: Pruebas HTTP estándar con solicitudes válidas
  - `incomplete`: Conexiones TCP incompletas que se establecen pero no se completan
  - `malformed`: Cabeceras HTTP deliberadamente malformadas y potencialmente maliciosas
  - `invalid`: Solicitudes HTTP completamente inválidas
  - `xss`: Pruebas de Cross-Site Scripting con payloads de inyección de JavaScript
  - `buffer`: Pruebas de desbordamiento de búfer con entradas extremadamente largas
  - `dos`: Pruebas de denegación de servicio con conexiones rápidas y múltiples solicitudes
  - `command`: Pruebas de inyección de comandos con payloads de inyección de comandos del sistema
  - `upload-standard`: Pruebas de subida de archivos estándar con contenido legítimo
  - `upload-malicious`: Pruebas de subida de archivos maliciosos con diferentes tipos de contenido peligroso
- Registro detallado de eventos en múltiples archivos de log
- Soporte para pruebas de duración fija o número de solicitudes por hilo
- Interfaz de usuario tipo Borland con mensaje de bienvenida

## Instalación

### Requisitos

- GCC (compilador de C)
- Libcurl development headers (`libcurl-dev` o `libcurl-devel`)
- pthread library
- make (opcional, para compilar desde Makefile)

### Compilación

```bash
gcc -o ost ophelia_stress_tool.c -lcurl -lpthread
```

O usando el Makefile si está disponible:

```bash
make
```

## Uso

### Sintaxis

```bash
./ost [OPCIONES]
```

### Opciones

- `-u, --urls FILE`: Archivo con lista de URLs a probar (requerido)
- `-t, --threads NUM`: Número de hilos concurrentes (por defecto: 5)
- `-r, --requests NUM`: Número de solicitudes por hilo (por defecto: 100)
- `-d, --duration SEC`: Duración máxima de la prueba en segundos (por defecto: 120)
- `-l, --log-dir DIR`: Directorio para guardar archivos de logs (por defecto: ./logs)
- `-T, --test-type TYPE`: Tipo de prueba a realizar (standard|incomplete|malformed|invalid|xss|buffer|dos|command|upload-standard|upload-malicious; por defecto: standard)
- `-h, --help`: Mostrar el mensaje de ayuda

### Ejemplos

```bash
# Prueba estándar con 10 hilos y 500 solicitudes por hilo
./ost -u urls.txt -t 10 -r 500

# Prueba de cabeceras malformadas con 5 hilos durante 180 segundos
./ost --urls urls.txt --test-type malformed --threads 5 --duration 180 --log-dir ./test_logs

# Prueba de conexiones incompletas
./ost --urls urls.txt --test-type incomplete --threads 10

# Prueba de solicitudes inválidas
./ost --urls urls.txt --test-type invalid --threads 5

# Prueba de subida de archivos estándar
./ost --urls urls.txt --test-type upload-standard --threads 5

# Prueba de subida de archivos maliciosos
./ost --urls urls.txt --test-type upload-malicious --threads 3
```

## Tipos de Pruebas

### Standard (`standard`)

Realiza solicitudes HTTP estándar y válidas usando la librería curl. Utiliza cabeceras HTTP comunes y bien formadas para probar el rendimiento normal de la aplicación.

### Incomplete Connections (`incomplete`)

Establece conexiones TCP con los servidores destino pero no completa la solicitud HTTP. Las conexiones se mantienen brevemente abiertas (50ms) antes de cerrarse, lo que puede agotar los recursos del servidor destinatario.

### Malformed Headers (`malformed`)

Envía cabeceras HTTP deliberadamente malformadas, potencialmente maliciosas o inválidas, incluyendo:
- Cabeceras sin nombre o valor inválido
- Caracteres de nueva línea para inyección de cabecera HTTP
- Intentos de inyección SQL
- Intentos de traversía de directorios
- Intentos de XSS (Cross-Site Scripting)
- Cabeceras extremadamente largas

### Invalid Requests (`invalid`)

Envía solicitudes HTTP completamente inválidas como:
- Métodos HTTP inexistentes
- Versiones HTTP inválidas (por ejemplo, HTTP/2.0)
- Conflictos en Content-Length
- Duplicados en cabeceras prohibidos
- Cabeceras con caracteres o valores inapropiados

### Cross-Site Scripting (`xss`)

Envía payloads específicos de inyección de JavaScript y XSS a través de diferentes parámetros y cabeceras HTTP para probar la susceptibilidad a ataques XSS en la aplicación.

### Buffer Overflow (`buffer`)

Envía entradas extremadamente largas y potencialmente maliciosas para probar la resistencia de la aplicación a ataques de desbordamiento de búfer, incluyendo cabeceras HTTP excesivamente largas y datos de gran tamaño en solicitudes.

### Denegación de Servicio (`dos`)

Realiza conexiones rápidas y múltiples solicitudes para intentar agotar los recursos del servidor y causar una denegación de servicio, incluyendo conexiones rápidas sin esperar respuesta completa.

### Command Injection (`command`)

Envía payloads específicos de inyección de comandos del sistema a través de diferentes parámetros y cabeceras HTTP para probar la susceptibilidad a ejecución de comandos arbitrarios.

### Upload Standard (`upload-standard`)

Realiza pruebas de subida de archivos estándar con contenido legítimo para probar la funcionalidad normal de subida de archivos, verificando que el sistema maneje correctamente archivos válidos.

### Upload Malicious (`upload-malicious`)

Realiza pruebas de subida de archivos maliciosos con diferentes tipos de contenido peligroso, incluyendo archivos PHP con comandos ejecutables, código JavaScript/XSS, códigos SQL Injection, archivos binarios sospechosos e intentos de buffer overflow. También incluye técnicas de evasión como extensiones dobles (por ejemplo, `image.jpg.php`) y diferentes tipos MIME para intentar eludir filtros de seguridad.

## Archivos de Log

La herramienta genera varios archivos de log en el directorio especificado:

- `success.log`: Solicitudes exitosas (respuesta HTTP 200-299)
- `errors.log`: Solicitudes con errores (cualquier otra respuesta o error de conexión)
- `malformed_headers.log`: Cabeceras malformadas específicas que se enviaron (solo para el tipo `malformed`)

## Archivo de URLs

El archivo de URLs debe contener una URL por línea, en formato estándar:

```
http://localhost:8000/
http://localhost:8000/api
http://localhost:8000/test
https://example.com/
https://example.com/endpoint
```

## Contribución

Las contribuciones son bienvenidas. Por favor, cree un fork del repositorio y envíe un pull request con sus cambios.

## Licencia

GNU GPL v3.0

## Desarrollado por

OPHELIA Project
Autores: Benjamin Sanchez Cardenas