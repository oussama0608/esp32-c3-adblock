# Test Plan

Estado a 2026-08-08: P2 incorpora 47 casos `pytest` con fixtures locales,
pequeñas y deterministas. La baseline limpia de P5.1 en `dce4672` termina con
**67 passed** y cero fallos bajo Python 3.13. Los tests no descargan blocklists
ni acceden deliberadamente a Internet: `urlopen` está bloqueado por defecto y la
única descarga simulada usa bytes locales controlados. Una persona confirmó
verdes los dos jobs de GitHub Actions para `dce4672`. Ese resultado no acredita
automáticamente la candidate P5.2 hasta ejecutar CI sobre su revisión exacta.

## Build

P3 ejecuta `pio run` automáticamente en Windows Server 2022 con el toolchain
fijado, sin upload, monitor ni hardware. Esto complementa, pero no sustituye, el
build nativo en Windows 10 ni las pruebas posteriores sobre la placa. Deben
registrarse el código de salida, warnings y tamaños de RAM, flash y
`firmware.bin` en cada entrega.

## P5.1 — retirada de OTA de firmware por red

Implementado y committed en `dce4672`, con gates permanentes en
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
La clean candidate final produjo 1.274.960 B físicos, 1.234.851 B de flash
enlazada y 51.164 B de RAM, con SHA-256
`BA22CE059C06CD86FBBFA5D1411261C85533DB22F92C4A555E83235F5637FA9E`.
El slot conserva 101.296 B físicos libres.

La inspección posterior de binario, ELF y mapa no encuentra `ArduinoOTA`,
handlers/strings de firmware OTA ni la cadena exacta `/update`. Permanece
`/update.cfg`, que pertenece exclusivamente a la configuración de actualización
de blocklist y no es una ruta HTTP de firmware.

La persona responsable confirmó ambos jobs de CI verdes. El HIL end-to-end de
la SuperMini validó SoftAP, DHCP, portal, guardado, reboot, STA, dashboard y DNS
bloqueado/permitido. También demostró que esa placa era inestable a la potencia
TX por defecto y estable a 8,5 dBm tanto en AP como en STA. Permanecen como gates
específicos la prueba explícita 404/405 de `/update`, ausencia del anuncio/puerto
ArduinoOTA y cualquier prueba destructiva del procedimiento
[USB_RECOVERY_WINDOWS.md](USB_RECOVERY_WINDOWS.md).

## P5.2 — seguridad del panel administrativo

La candidate añade 32 tests estáticos permanentes en
`tests/test_p5_2_admin_security.py`. La ejecución local final de la revisión
completa terminó con **99 passed** y cero fallos bajo Python 3.13. Los gates
comprueban:

- PBKDF2-HMAC-SHA-256 con 50.000 iteraciones, salt de 16 bytes, verificador de
  32 bytes, RNG del ESP, comparación constant-time y limpieza de buffers;
- ausencia de contraseña administrativa hardcoded y ausencia de persistencia de
  contraseña, sesión o CSRF; NVS solo admite el registro versionado del
  verificador;
- contraseña entre 12 y 128 bytes y bootstrap/restablecimiento fail-closed bajo
  autorización física BOOT;
- tokens de sesión y CSRF independientes y aleatorios, solo en RAM, expiración a
  30 minutos, invalidación por logout y cookie con `HttpOnly`,
  `SameSite=Strict`, `Path=/` y duración acotada;
- throttle de login creciente y acotado, sin lockout persistente;
- recolección y allowlist de `Host` para IPv4 local o `c3adblock.local`, manejo
  explícito de `:80` y rechazo de valores arbitrarios/malformados;
- matriz de rutas: lecturas administrativas con sesión y todas las mutaciones
  únicamente por POST con sesión y CSRF, incluidos `/upload`, `/fetchnow`,
  `/setupdate`, custom block/unblock, ban, logout y forget-Wi-Fi;
- token CSRF separado para `/wifisave` dentro del portal físicamente autorizado;
- escape HTML de `&`, `<`, `>`, comilla doble y comilla simple, escape JSON,
  construcción DOM sin HTML ejecutable y script separado de los datos;
- headers `no-store`, `nosniff`, `no-referrer` y CSP compatible con el dashboard;
- redirect fijo de la raíz no autenticada a `/login` después de validar `Host`,
  y error de compilación si el core se configura en nivel `VERBOSE`, porque
  `WebServer` podría registrar cuerpos de formularios sensibles;
- regresiones de P5.1: `/update`/ArduinoOTA/Update ausentes, un único
  `WiFi.begin`, workaround RF a 8,5 dBm y archivos protegidos intactos.

Estos gates son inspección de invariantes del código; no sustituyen ejecutar el
firmware ni un navegador. Antes de aceptar P5.2 quedan pendientes:

- crear y restablecer la contraseña con BOOT en la placa exacta, y verificar que
  sin presencia física el bootstrap y `/wifisave` fallan cerrados;
- login correcto/incorrecto, escalado del throttle, logout, sustitución de la
  sesión, expiración a 30 minutos y pérdida de sesión tras reboot;
- probar IPv4, `c3adblock.local`, `:80`, Host vacío/malformado/arbitrario y que
  ninguna respuesta use Host no confiable para construir un redirect;
- matriz HTTP real con GET/POST/métodos alternativos, sesión ausente/expirada y
  CSRF ausente/incorrecto/repetido para cada mutación y upload multipart;
- corpus XSS en navegador para dominio, URL, estado, SSID y datos persistidos
  legacy, verificando CSP y que el contenido solo aparece como texto;
- smoke DNS/panel y medición de heap durante PBKDF2/login; comprobar que el
  canal HTTP claro no se confunde con confidencialidad.

### P5.2a — autorización física BOOT en runtime

Los tests permanentes sustituyen el gate que exigía la doble lectura destructiva
de GPIO9 durante `setup()` y comprueban ahora:

- `setup()` solo configura el pull-up y no autoriza ni borra estado a partir de
  una lectura temprana del pin de strapping;
- una máquina no bloqueante basada en `millis()` se arma únicamente después de
  observar BOOT liberado, reinicia el conteo ante release/rebote y no ejecuta la
  acción con una pulsación corta;
- el portal exige LOW continuo durante al menos 3 s, borra Wi-Fi/verificador,
  rota el CSRF de provisioning y habilita `/wifisave` sin reboot; tras guardar,
  el reboot queda diferido hasta observar BOOT liberado de forma estable;
- el modo STA exige LOW continuo durante al menos 5 s, borra Wi-Fi/verificador,
  zeroiza sesión/CSRF y espera una liberación estable antes del reboot;
- el fallo de `WiFi.softAP()` queda antes de RNG, DNS, web y mensaje de éxito,
  sin reboot loop ni anuncio de un portal inexistente;
- las instrucciones de provisioning exigen firmware ya arrancado y nunca BOOT
  durante reset/power-on; la secuencia BOOT+RESET queda reservada al downloader
  ROM documentado por separado;
- permanecen los gates P5.2 de auth/sesión/CSRF/Host/XSS y los invariantes P5.1
  de OTA ausente, RF a 8,5 dBm y archivos protegidos.

Estos son gates estructurales host. El HIL debe comprobar tiempos/rebote reales,
persistencia borrada, refresh de formulario, reinicio tras release y fallo AP;
no se considera validado físicamente hasta ejecutar esa matriz en la SuperMini.
La validación local P5.2a terminó con **105 passed**, Ruff y diff checks limpios;
PlatformIO enlazó 1.250.561 B y generó un `firmware.bin` de 1.292.272 B. Quedan
83.984 B físicos en el slot, por encima del gate de 64 KiB. Esto no equivale a
HIL ni autoriza un flash.

P5.2 protege el acceso a upload/fetch, pero no prueba ni corrige todavía
atomicidad, last-known-good, autenticidad, TLS, `setInsecure()` o SSRF.

El build local final enlaza 1.249.513 B (90,8 %) y usa 51.292 B de RAM estática
(15,7 %). `firmware.bin` mide 1.291.104 B, SHA-256
`F87A9498C1E182A72E881C9C4BFBEE1AF2F2ACF9694A0B4352F0366278EB5463`, y deja
85.152 B físicos (83,16 KiB) en el slot. Supera el margen mínimo de parada de
64 KiB, pero sigue siendo estrecho y no autoriza un flash ni un piloto.

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

- ejecución real de la candidate P5.2 en GitHub y confirmación humana de ambos
  jobs para su revisión exacta;
- decidir si los checks serán obligatorios mediante branch protection;
- mantener pruebas de Windows 10 real, hardware, red, DNS y panel ya enumeradas.

La ejecución verde confirmada de `dce4672` valida esa revisión, no cambios
posteriores. La inspección estructural o el parseo local del YAML tampoco
acreditan una ejecución nueva.

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

- P5.2 auth/session/CSRF/Host/XSS en navegador y placa;
- portal físico BOOT: hold runtime de 3 s, pulsación corta/rebote, bootstrap y
  recuperación de contraseña fail-closed;
- medición de tiempo/heap mínimo durante PBKDF2 y repetidos logins fallidos;
- 24 horas y 7 días;
- varios clientes;
- reinicio router;
- cambio Wi-Fi;
- recuperación BOOT desde STA con hold de 5 s, release antes de reboot y regreso
  al portal read-only.

La baseline `dce4672` ya completó HIL end-to-end con alimentación independiente,
SoftAP/DHCP/portal, STA, dashboard y DNS; no sustituye las pruebas P5.2 anteriores.

## Piloto mínimo — pendiente

- cero reinicios inesperados en 7 días;
- cero secretos;
- recuperación documentada;
- panel protegido;
- versión identificable;
- limitaciones entregadas.
