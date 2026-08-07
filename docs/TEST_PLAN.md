# Test Plan

Estado a 2026-08-07: P2 incorpora 47 casos `pytest` con fixtures locales,
pequeñas y deterministas. P5.1 añade 17 gates estáticos y de artefactos; la suite
local actual termina con **64 passed** y cero fallos bajo Python 3.13. Los tests
no descargan blocklists ni acceden deliberadamente a Internet: `urlopen` está
bloqueado por defecto y la única descarga simulada usa bytes locales
controlados. P3 añade CI reproducible; la validación local no equivale a una
ejecución satisfactoria en GitHub Actions.

## Build

P3 ejecuta `pio run` automáticamente en Windows Server 2022 con el toolchain
fijado, sin upload, monitor ni hardware. Esto complementa, pero no sustituye, el
build nativo en Windows 10 ni las pruebas posteriores sobre la placa. Deben
registrarse el código de salida, warnings y tamaños de RAM, flash y
`firmware.bin` en cada entrega.

## P5.1 — retirada de OTA de firmware por red

Implementado localmente con 17 casos nuevos en
`tests/test_p5_1_no_network_firmware_ota.py`:

- ausencia en `src/` de `ArduinoOTA`, `Update.h`, APIs `Update`, handlers de
  firmware, marcadores `[fw-ota]` y APIs OTA alternativas obvias;
- ausencia de la ruta HTTP exacta `/update`, conservando como control positivo
  `/upload`, `/fetchnow` y `/setupdate` para la blocklist;
- ausencia del formulario, botón, JavaScript, mensajes y referencia al binario
  de firmware en `src/page.h`;
- el README deja de presentar la OTA de firmware, `espota` y el instalador web
  legacy como funciones disponibles;
- ambos installers muestran un aviso visible `legacy`, deshabilitado e inseguro,
  no cargan scripts/herramientas ni enlazan binarios, y sus manifests tienen
  `status: legacy-disabled` y `builds: []` sin partes instalables;
- los diez binarios legacy se conservan con los SHA-256 auditados, sin
  regenerarlos ni presentarlos como instalación soportada;
- SHA-256 exacto de `partitions.csv`, complementado por los gates P3 de blob Git,
  slots y `git diff --exit-code`.

El build limpio pre-P5.1 medido en `a282e56` produjo 1.298.656 B físicos,
53.124 B de RAM estática y SHA-256
`7BB4BB3F06A9757492A847DA7B4CA36F9C39D6A0A3FD60EA7026EB66355A74CE`.
El build limpio posterior produjo 1.274.224 B, 51.164 B de RAM y SHA-256
`DEAEEE6885A8446D678FACC7141F093E3B4061F54C7DFF76CD1693AFB1401367`.
Son 24.432 B físicos y 1.960 B de RAM menos; el slot conserva 102.032 B libres.

La inspección posterior de binario, ELF y mapa no encuentra `ArduinoOTA`,
handlers/strings de firmware OTA ni la cadena exacta `/update`. Permanece
`/update.cfg`, que pertenece exclusivamente a la configuración de actualización
de blocklist y no es una ruta HTTP de firmware.

Pendiente antes de cerrar las amenazas asociadas:

- ejecución real de la CI para la revisión P5.1, confirmada por una persona;
- HIL autorizado que compruebe 404/405 de `/update` y ausencia de anuncio/puerto
  ArduinoOTA;
- smoke de regresión DNS/panel y validación física del procedimiento
  [USB_RECOVERY_WINDOWS.md](USB_RECOVERY_WINDOWS.md).

## Integración continua — implementado en P3

`.github/workflows/ci.yml` valida los pushes y pull requests dirigidos a `main`
y `develop`, además de permitir ejecución manual mediante `workflow_dispatch`.
El workflow solo concede `contents: read` al `GITHUB_TOKEN`. No usa GitHub
Secrets, credenciales Wi-Fi, hardware, upload, monitor, caché, artefactos,
releases ni deployment.

El job `python-quality` usa Python 3.13.12 y ejecuta:

- comprobación de contenido protegido e indicadores obvios de secretos en
  archivos rastreados;
- inspección estructural de la política del propio workflow y de los SHA de las
  Actions;
- `pytest -q` con las fixtures locales de P2;
- `ruff check . --no-cache`;
- `git diff --check` y rechazo de cambios rastreados inesperados.

La fixture automática de pytest bloquea `urlopen` en el generador y la única
descarga simulada usa bytes locales. Esto evita descargas deliberadas de
blocklists, pero no constituye un sandbox general de red para el runner.

El job `firmware-build` usa Python 3.13.12 y PlatformIO Core 6.1.19. Conserva
exactamente la plataforma ESP32 fijada en P1, almacena `PLATFORMIO_CORE_DIR`
dentro del workspace, genera una blocklist de 35 bytes exclusivamente desde las
fixtures locales y ejecuta únicamente `pio run`.

Después del build, CI mide `.pio/build/c3/firmware.bin` y lo compara con los
slots `app0` y `app1` actuales de 1.376.256 bytes. Imprime bytes usados, libres y
porcentaje, y falla si la imagen supera físicamente el slot. La medición local
de P3 deja aproximadamente 77,6 KB libres; no se aplica todavía un límite
comercial adicional.

También se comprueba que `partitions.csv` y `LICENSE` conservan sus blobs Git
aprobados, que ambos slots mantienen el tamaño esperado, que `LICENSE` sigue
presente y no vacío, y que `src/secrets.h` no está versionado. La búsqueda de
secretos cubre indicadores de alta confianza y asignaciones literales obvias,
pero no sustituye una auditoría especializada.

## Integración continua — pendiente

- primera ejecución real del workflow en GitHub;
- confirmar disponibilidad de versiones y comportamiento de las Actions en los
  runners alojados;
- confirmar tiempo y resultado de un build limpio sin caché;
- decidir si los checks serán obligatorios mediante branch protection;
- pruebas de Windows 10 real, hardware, red, DNS, panel y OTA ya enumeradas.

La inspección estructural o el parseo local del YAML no acreditan que GitHub
Actions haya aceptado ni ejecutado el workflow.

## Python — implementado en P2

- lectura de una entrada de dominio por línea y de hosts con `0.0.0.0` o
  `127.0.0.1`;
- comentarios, líneas vacías y duplicados;
- normalización a minúsculas, retirada de puntos extremos, prefijo `www.` y
  wildcard inicial según la política vigente (`*.example.com` se convierte en
  `example.com`);
- rechazo de sintaxis inválida, literales IP, dominios de más de 253 caracteres
  y labels DNS de más de 63 caracteres, incluidos sus valores límite;
- FNV-1a de 64 bits truncado a 40 bits con cuatro vectores conocidos;
- serialización en cinco bytes little-endian, orden numérico ascendente y
  eliminación de hashes duplicados;
- colisiones forzadas de dominios distintos: deduplicación del hash, conteo y
  reporte en la salida de la CLI;
- tamaño del archivo binario múltiplo de cinco y rechazo de blobs desalineados;
- límite máximo configurable mediante `--max-bytes`, incluido el borde exacto
  permitido y el rechazo sin reemplazo al excederlo;
- lectura local y descarga HTTP simulada sin tráfico de red;
- fallo parcial de fuentes con aprovechamiento de una fuente válida;
- fallo total de fuentes con salida distinta de cero, sin crear un blob vacío y
  preservando una blocklist anterior;
- fuente legible sin dominios válidos: fallo y preservación del destino;
- temporal completo en el mismo directorio, cerrado antes de `os.replace`, y
  limpieza del temporal si falla el reemplazo.

## Python — pendiente

- vectores compartidos con un harness C++ que compruebe paridad exacta con el
  hash del firmware;
- property-based testing o fuzz del parser de listas;
- pruebas de corte del proceso o alimentación durante la sustitución y de la
  semántica atómica en todos los filesystems soportados;
- validación de procedencia, revisión y autenticidad de fuentes reales, sin
  convertir las descargas de Internet en requisito de pytest.

## DNS — pendiente

- A, AAAA y EDNS;
- paquetes truncados o inválidos;
- compression pointers;
- múltiples preguntas;
- tipos no soportados;
- fuzz básico.

## Integración — pendiente

- bloqueado;
- permitido;
- upstream caído;
- Wi-Fi perdido;
- blocklist ausente o corrupta;
- actualización interrumpida;
- reinicio durante escritura;
- allowlist.

## Hardware — pendiente

- alimentación USB desde el host Windows, cargador y router;
- RSSI;
- 24 horas y 7 días;
- varios clientes;
- reinicio router;
- cambio Wi-Fi;
- recuperación BOOT.

## Piloto mínimo — pendiente

- cero reinicios inesperados en 7 días;
- cero secretos;
- recuperación documentada;
- panel protegido;
- versión identificable;
- limitaciones entregadas.
