# NetShield Mini — Codex Starter para Windows 10

Entorno previsto:

- MacBook Pro 2011 Intel ejecutando Windows 10 de 64 bits.
- PowerShell o Windows Terminal.
- VS Code.
- Codex CLI nativo para Windows.
- Python y PlatformIO nativos para facilitar el acceso al ESP32 mediante `COMx`.

## Decisión de entorno

Para este proyecto se recomienda trabajar de forma nativa en Windows, no dentro
de WSL, porque el flasheo y el monitor serie del ESP32 resultan más directos desde
PlatformIO usando el puerto `COMx`.

Windows 10 debe estar completamente actualizado. Codex ofrece soporte de mejor
esfuerzo en versiones recientes de Windows 10; Windows 11 es el entorno recomendado,
pero no es necesario cambiar de ordenador para comenzar este prototipo.

## Orden

1. Ejecutar `winver` y confirmar Windows 10 versión 1809 o posterior.
2. Instalar Git, Python, VS Code y Codex.
3. Ejecutar `scripts\bootstrap_windows.ps1`.
4. Crear un fork de `M-Abozaid/esp32-c3-adblock`.
5. Clonar el fork con `scripts\clone_upstream.ps1`.
6. Copiar los archivos de este starter a la raíz del repositorio clonado.
7. Abrir el repositorio con VS Code.
8. Ejecutar Codex desde PowerShell en la raíz del repositorio.
9. Empezar únicamente por P0 en `CODEX_PROMPTS.md`.
10. No conectar ni flashear hasta que compile.

## Primer MVP

- build reproducible en Windows 10 x64;
- blocklist reproducible;
- detección automática o manual de `COMx`;
- DNS permitido y bloqueado;
- recuperación Wi-Fi;
- cero credenciales en Git;
- prueba continua de siete días.
