# Architecture Decision Records

## ADR-001 — Toolchain reproducible para Windows 10 x64

- Fecha: 2026-08-06
- Estado: accepted
- Contexto: el build limpio fallaba porque PlatformIO intentaba escribir en el
  Core global del usuario, `espressif32` no tenía versión fijada, los puertos
  serie apuntaban a Linux y `src/secrets.h` era obligatorio aunque no estaba en
  Git. Los binarios upstream contienen Arduino-ESP32 3.3.7 y ESP-IDF 5.5.2.
- Decisión: usar Python 3.13.12 y PlatformIO Core 6.1.19 con
  `PLATFORMIO_CORE_DIR` y `core_dir` apuntando a `.platformio/` dentro del
  repositorio. Fijar `pioarduino`
  55.03.37, que fija a su vez Arduino-ESP32 3.3.7 y sus librerías ESP-IDF 5.5.2.
  Mantener `framework = arduino`, eliminar los puertos serie fijos para permitir
  la autodetección de `COMx` y hacer opcional `src/secrets.h`, con credenciales
  vacías como fallback. Normalizar texto a LF y marcar BIN/STL como binarios.
- Alternativas: la plataforma oficial `platformio/espressif32` 6.12.0 y 7.0.1
  todavía fijan Arduino-ESP32 2.0.17 sobre ESP-IDF 4.4.7 y no reproducen el
  toolchain observado. Sobrescribir solo el framework podría desalinearlo de
  sus librerías precompiladas, por lo que se descartó.
- Consecuencias: el primer build descarga únicamente plataforma, framework y
  herramientas de compilación dentro de `.platformio/`. `pioarduino` es un fork
  comunitario, aunque consume los artefactos oficiales de Espressif. La versión
  55.03.37 acepta Python 3.10–3.13 en Windows y rechaza Python 3.14. Un
  `secrets.h` local seguirá prevaleciendo y hará que ese binario contenga las
  credenciales del desarrollador; nunca debe versionarse.
- Verificación: una blocklist explícita de dos entradas se generó sin red. El
  build terminó con exit 0 y PlatformIO reportó 53.124/327.680 bytes de RAM
  (16,2 %) y 1.254.885/1.376.256 bytes de flash (91,2 %). Ruff terminó con exit
  0. Pytest terminó con exit 5 y `no tests ran`; la cobertura automatizada queda
  pendiente. No se cambió `partitions.csv`, no se flasheó ni se abrió un puerto
  serie.
