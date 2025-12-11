# Changelog

Toda las modificaciones notables a la herramienta `ophelia_stress_tool` serán documentadas en este archivo.

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
