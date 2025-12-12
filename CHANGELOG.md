# Changelog

Toda las modificaciones notables a la herramienta `ophelia_stress_tool` serán documentadas en este archivo.

## [5.1.0] - 2025-12-11

### Agregado
- Nuevo tipo de prueba: `upload-standard` - Pruebas de subida de archivos estándar con contenido legítimo
- Nuevo tipo de prueba: `upload-malicious` - Pruebas de subida de archivos maliciosos con diferentes tipos de contenido peligroso (PHP, XSS, SQL injection, buffer overflow, etc.)
- Nuevas técnicas de evasión en pruebas de subida de archivos: extensiones dobles (por ejemplo, `image.jpg.php`), diferentes tipos MIME fraudulentos
- Registro detallado de intentos de subida de archivos maliciosos que puedan evadir filtros de seguridad
- Se amplió el número total de tipos de prueba a 10: standard, incomplete, malformed, invalid, xss, buffer, dos, command, upload-standard, upload-malicious

### Cambiado
- Versión actualizada de la herramienta a 5.1.0 para reflejar la importante expansión de funcionalidad
- La ayuda ahora incluye el parámetro `-T` con los tipos disponibles: `standard|incomplete|malformed|invalid|xss|buffer|dos|command|upload-standard|upload-malicious`
- Se agregaron nuevas constantes de enumeración para los nuevos tipos de prueba
- Actualización de la lógica de selección de función según el tipo de prueba para incluir las nuevas pruebas de subida de archivos

### Mejorado
- Se mejoró la capacidad de prueba de seguridad de la herramienta, cubriendo ahora también vulnerabilidades relacionadas con subida de archivos
- Se agregaron payloads específicos para pruebas de subida de archivos que pueden revelar vulnerabilidades en validaciones de tipo de archivo
- Los logs ahora registran información detallada sobre las pruebas de subida de archivos

## [5.0.0] - 2025-12-11

### Agregado
- Nuevo tipo de prueba: `xss` - Pruebas de Cross-Site Scripting con payloads de inyección de JavaScript
- Nuevo tipo de prueba: `buffer` - Pruebas de desbordamiento de búfer con entradas extremadamente largas
- Nuevo tipo de prueba: `dos` - Pruebas de denegación de servicio con conexiones rápidas y múltiples solicitudes
- Nuevo tipo de prueba: `command` - Pruebas de inyección de comandos con payloads de inyección de comandos del sistema
- Se amplió el número total de tipos de prueba a 8: standard, incomplete, malformed, invalid, xss, buffer, dos, command
- Se agregaron nuevas entradas detalladas a la ayuda del programa para los nuevos tipos de prueba
- Inclusión de payloads específicos que pueden provocar cuelgues en servidores vulnerables

### Cambiado
- Versión actualizada de la herramienta a 5.0.0 para reflejar la importante expansión de funcionalidad
- La ayuda ahora incluye el parámetro `-T` con los tipos disponibles: `standard|incomplete|malformed|invalid|xss|buffer|dos|command`
- Se agregaron nuevas constantes de enumeración para los nuevos tipos de prueba
- Actualización de la lógica de selección de función según el tipo de prueba para incluir las nuevas pruebas

### Mejorado
- Se mejoró la capacidad de prueba de seguridad de la herramienta, ampliando desde pruebas generales a pruebas específicas de vulnerabilidades
- Se aumentó la efectividad de la herramienta en la detección de vulnerabilidades de seguridad
- Se agregaron payloads más agresivos y variados para diferentes tipos de pruebas de seguridad

## [4.0.0] - 2025-12-11

### Agregado
- Nuevo tipo de prueba: `incomplete` - Conexiones TCP incompletas que se establecen pero no se completan
- Nuevo tipo de prueba: `malformed` - Cabeceras HTTP deliberadamente malformadas y potencialmente maliciosas
- Nuevo tipo de prueba: `invalid` - Solicitudes HTTP completamente inválidas
- Nuevo archivo de log: `malformed_headers.log` para registrar las cabeceras malformadas enviadas
- Registro detallado de intentos de inyección SQL, XSS, traversía de directorios y cabeceras extremadamente largas
- Registro de conexiones incompletas con información sobre host, puerto y duración
- Registro de solicitudes inválidas con detalles específicos de la solicitud enviada

### Cambiado
- El tipo de prueba original con curl ahora se llama `standard` (anteriormente era la única opción)
- Versión actualizada de la herramienta a 4.0.0 para reflejar el importante cambio de funcionalidad
- La ayuda ahora incluye el parámetro `-T` con los tipos disponibles: `standard|incomplete|malformed|invalid`
- La estructura `thread_data_t` ahora incluye el campo `test_type` para identificar el tipo de prueba

### Mejorado
- Se agregaron cabeceras malformadas más agresivas para probar la resistencia del sistema
- Los logs ahora registran información detallada sobre las pruebas realizadas según su tipo
- Mejor manejo de errores y registro de eventos específicos según el tipo de prueba
- Sistema de logging más detallado que permite rastrear diferentes tipos de pruebas y sus resultados

## [3.2.1] - 2025-10-15

### Original
- Versión inicial de la herramienta de pruebas de estrés OPHELIA
- Pruebas de estrés estándar usando solicitudes HTTP con libcurl
- Registro de éxitos y errores en archivos de log