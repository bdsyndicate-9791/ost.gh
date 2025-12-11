CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99 -D_DEFAULT_SOURCE
LIBS = -lcurl -lpthread

TARGET = ost
SOURCE = ophelia_stress_tool.c

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/ost
	sudo chmod +x /usr/local/bin/ost
	@echo "ophelia_stress_tool (PLUS) instalado en /usr/local/bin/"

uninstall:
	sudo rm -f /usr/local/bin/ost
	@echo "ophelia_stress_tool desinstalado de /usr/local/bin/"

clean:
	rm -f $(TARGET)

dist-clean: clean
	rm -f *~

help:
	@echo "Opciones disponibles:"
	@echo "  make all       - Compila el programa"
	@echo "  make install   - Instala la versión PLUS en /usr/local/bin/ con nombre estándar"
	@echo "  make uninstall - Desinstala el programa"
	@echo "  make clean     - Limpia los archivos compilados"
	@echo "  make dist-clean - Limpia completamente"
	@echo "  make help      - Muestra este mensaje"