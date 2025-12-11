# Documentación del OPHELIA Stress Testing Tool (Marketing)

## ¿Qué es?

El **OPHELIA Stress Testing Tool (Marketing)** es una aplicación de línea de comandos escrita en C que permite realizar pruebas de estrés a aplicaciones OPHELIA u otras aplicaciones web mediante solicitudes HTTP concurrentes. La herramienta fue desarrollada específicamente para evaluar la capacidad de carga, rendimiento y estabilidad de sistemas bajo condiciones de alta demanda.

## ¿Para qué sirve?

Este software sirve para:

1. **Evaluar el rendimiento de aplicaciones web:** Medir cómo responde un sistema cuando recibe múltiples solicitudes simultáneas
2. **Identificar cuellos de botella:** Detectar puntos débiles en el sistema antes de que ocurran en producción
3. **Verificar la estabilidad:** Determinar si una aplicación puede mantenerse operativa bajo carga prolongada
4. **Pruebas de carga controladas:** Simular escenarios reales de uso intensivo de manera segura y controlada
5. **Generar métricas de rendimiento:** Obtener datos cuantitativos sobre tiempos de respuesta, tasas de éxito/error, etc.

## ¿Qué hace?

La herramienta realiza las siguientes acciones principales:

1. **Lee una lista de URLs** desde un archivo de texto
2. **Inicia múltiples hilos concurrentes** que realizan solicitudes HTTP a las URLs
3. **Selecciona aleatoriamente URLs** de la lista para cada solicitud
4. **Registra métricas detalladas** de cada solicitud (tiempo de respuesta, código de estado, etc.)
5. **Almacena los resultados** en archivos de log (éxitos y errores separadamente)
6. **Calcula estadísticas generales** del rendimiento (tasa de éxito, RPS, etc.)
7. **Presenta un informe final** con los resultados de la prueba

## ¿Cómo lo hace?

El proceso técnico de la herramienta es el siguiente:

### Arquitectura multihilo
- Utiliza la biblioteca `pthread` para crear múltiples hilos de ejecución
- Cada hilo opera independientemente y mantiene sus propias estadísticas
- Los hilos comparten la lista de URLs pero acceden a diferentes posiciones

### Uso de libcurl
- Emplea la biblioteca `libcurl` para realizar las solicitudes HTTP
- Configura timeouts y opciones de seguridad apropiadas
- Maneja tanto solicitudes exitosas como fallidas

### Control de parámetros
- Permite configurar el número de hilos concurrentes (por defecto 5)
- Controla el número de solicitudes por hilo o duración total de la prueba
- Acepta como entrada un archivo con la lista de URLs a probar

### Registro y métricas
- Escribe logs detallados de cada solicitud en archivos separados para éxitos y errores
- Calcula tiempos de respuesta promedio, tasas de éxito/error
- Genera estadísticas globales como solicitudes por segundo (RPS)

### Gestión de recursos
- Implementa gestión adecuada de memoria dinámica (malloc/free)
- Maneja errores de red y de sistema de forma robusta
- Limita la tasa de solicitudes para distribuir la carga uniformemente

### Interfaz de usuario
- Presenta una pantalla de presentación estilo Borland con información del software
- Proporciona una interfaz de línea de comandos intuitiva con opción de ayuda
- Muestra estado en tiempo real durante la ejecución de la prueba
- Ofrece un informe final detallado con todas las métricas relevantes

La herramienta está especialmente diseñada para integrarse en el ecosistema OPHELIA y proporcionar pruebas de estrés confiables y reproducibles para sistemas de alta disponibilidad.