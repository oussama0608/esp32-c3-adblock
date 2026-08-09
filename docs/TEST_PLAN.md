# Test Plan

Estado a 2026-08-08: P2 incorpora 47 casos `pytest` con fixtures locales,
pequeñas y deterministas. La baseline limpia de P5.1 en `dce4672` termina con
**67 passed** y cero fallos bajo Python 3.13. Los tests no descargan blocklists
ni acceden deliberadamente a Internet: `urlopen` está bloqueado por defecto y la
única descarga simulada usa bytes locales controlados. Una persona confirmó
verdes los dos jobs de GitHub Actions para `dce4672`. P5.2 y P5.2a están
committed y pushed en `bbeacda`; una persona confirmó verdes sus dos jobs de CI
y el HIL completo solicitado. Esa evidencia acredita `bbeacda`, no P5.3a ni
ningún cambio posterior.

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
- ausencia de la ruta HTTP exacta `/update`. `/upload` se conserva como control
  positivo para blocklist; P5.3a retira posteriormente `/fetchnow` y `/setupdate`;
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
handlers/strings de firmware OTA ni la cadena exacta `/update`. En P5.1
permanecía `/update.cfg`, que pertenecía exclusivamente a la configuración de
actualización de blocklist y no era una ruta HTTP de firmware. P5.3a elimina
toda referencia de producción a ese nombre: un archivo legacy queda inerte y su
contenido nunca se abre ni se interpreta.

La persona responsable confirmó ambos jobs de CI verdes. El HIL end-to-end de
la SuperMini validó SoftAP, DHCP, portal, guardado, reboot, STA, dashboard y DNS
bloqueado/permitido. También demostró que esa placa era inestable a la potencia
TX por defecto y estable a 8,5 dBm tanto en AP como en STA. Permanecen como gates
específicos la prueba explícita 404/405 de `/update`, ausencia del anuncio/puerto
ArduinoOTA y cualquier prueba destructiva del procedimiento
[USB_RECOVERY_WINDOWS.md](USB_RECOVERY_WINDOWS.md).

## P5.2 — seguridad del panel administrativo

La baseline P5.2 añade 32 tests estáticos permanentes en
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
- matriz de rutas de la baseline P5.2: lecturas administrativas con sesión y
  todas las mutaciones únicamente por POST con sesión y CSRF, incluidos entonces
  `/upload`, `/fetchnow`, `/setupdate`, custom block/unblock, ban, logout y
  forget-Wi-Fi. P5.3a elimina las dos rutas remotas;
- token CSRF separado para `/wifisave` dentro del portal físicamente autorizado;
- escape HTML de `&`, `<`, `>`, comilla doble y comilla simple, escape JSON,
  construcción DOM sin HTML ejecutable y script separado de los datos;
- headers `no-store`, `nosniff`, `no-referrer` y CSP compatible con el dashboard;
- redirect fijo de la raíz no autenticada a `/login` después de validar `Host`,
  y error de compilación si el core se configura en nivel `VERBOSE`, porque
  `WebServer` podría registrar cuerpos de formularios sensibles;
- regresiones de P5.1: `/update`/ArduinoOTA/Update ausentes, un único
  `WiFi.begin`, workaround RF a 8,5 dBm y archivos protegidos intactos.

Estos gates son inspección de invariantes del código; por sí solos no sustituyen
el firmware ni un navegador. Para la revisión committed y pushed `bbeacda`, una
persona confirmó ambos jobs de CI verdes y el HIL completo de P5.2/P5.2a. La
confirmación incluye la matriz física solicitada para BOOT, provisioning,
login/sesión/CSRF/Host, dashboard y regresión DNS. No elimina el riesgo residual
del panel HTTP claro ni acredita P5.3a.

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

Estos son gates estructurales host. La revisión `bbeacda` completó además el HIL
de tiempos/rebote reales, persistencia borrada, refresh de formulario, reinicio
tras release y comportamiento AP. P5.2a terminó localmente con **105 passed**,
Ruff y diff checks limpios; PlatformIO enlazó 1.250.561 B y generó un
`firmware.bin` de 1.292.272 B, dejando 83.984 B físicos. Una persona confirmó
también ambos jobs de CI verdes. Esta baseline validada no autoriza por sí sola
un piloto y no acredita la candidate P5.3a.

En esa baseline, P5.2 protegía el acceso a upload/fetch, pero aún no corregía
atomicidad, last-known-good, autenticidad, TLS, `setInsecure()` o SSRF. El delta
P5.3a actual se documenta a continuación.

El build local final enlaza 1.249.513 B (90,8 %) y usa 51.292 B de RAM estática
(15,7 %). `firmware.bin` mide 1.291.104 B, SHA-256
`F87A9498C1E182A72E881C9C4BFBEE1AF2F2ACF9694A0B4352F0366278EB5463`, y deja
85.152 B físicos (83,16 KiB) en el slot. Supera el margen mínimo de parada de
64 KiB, pero sigue siendo estrecho y no autoriza un flash ni un piloto.

## P5.3a — blocklist local transaccional y fetch remoto deshabilitado

P5.3a conserva exclusivamente el upload manual autenticado y elimina del
firmware, las rutas y la interfaz las funciones remotas `/fetchnow` y
`/setupdate`, su URL, intervalo y ejecución periódica. La interfaz mantiene DOM
seguro y muestra: «Las actualizaciones remotas de listas están desactivadas en
esta versión. Usa únicamente archivos de blocklist validados.» No se introduce
un sustituto HTTP/TLS ni se descarga una lista durante pytest.

Los gates automatizados de esta entrega deben cubrir:

- ausencia de `/fetchnow`, `/setupdate`, `HTTPClient`, `NetworkClientSecure`,
  `WiFiClientSecure`, `setInsecure()` y del scheduler de fetch en el firmware
  actual;
- permanencia de `/upload` como POST con sesión y CSRF, sin recuperar rutas de
  firmware OTA;
- montaje LittleFS sin autoformato y recuperación antes de leer estado o iniciar
  STA, SoftAP, mDNS, DNS o el servidor HTTP;
- ausencia de URL/intervalo remoto y de sus listeners en `src/page.h`, junto al
  mensaje español aprobado y al upload manual;
- validación completa del candidato `/blocklist.new` antes de sustituir el
  activo `/blocklist.bin`, manteniendo `/blocklist.old` como rollback durante la
  transacción. El máximo común de generador y firmware es 104.857 registros de
  cinco bytes, 524.285 bytes en total;
- autorización antes de abrir el candidato, límite por cada chunk, comprobación
  de cada write, abort/short write/overflow sin tocar el activo, respuesta 413
  por exceso y rechazo 409 de una transacción reentrante;
- dispatcher por `Content-Type`: multipart es el único upload aceptado; cuerpos
  raw/urlencoded se rechazan con 415 sin acceder a `web.upload()` ni crear candidato;
- recuperación determinista al arrancar: un activo válido gana y limpia restos;
  sin activo válido se restaura un rollback válido; sin ambos se promueve un
  candidato válido; si no existe ninguna copia válida se falla cerrado;
- candidato inválido nunca reemplaza un activo válido, y hashes/entradas solo se
  cargan desde un archivo que supera las validaciones de formato y tamaño;
- un activo legacy válido por encima de 524.285 bytes permanece legible, pero no
  amplía el límite de candidatos ni se elimina si el staging se queda sin espacio;
- `/update.cfg` ya no aparece en el código de producción: cualquier copia legacy
  queda ignorada e inerte, sin poder reactivar fetch remoto. El archivo físico
  puede conservar una URL o token antiguo y ocupar espacio hasta una restauración
  explícita de LittleFS;
- regresiones permanentes de P5.1/P5.2a, `partitions.csv`, `LICENSE` y
  `platformio.ini` intactos.

La matriz de recuperación ante corte esperada es:

1. Durante el upload: el activo válido gana y el candidato parcial se elimina.
2. Después de cerrar el candidato: el activo válido gana; el candidato, sea
   válido o inválido, se trata como staging no confirmado y se elimina.
3. Después de validar el candidato pero antes de `active -> old`: el activo
   válido sigue ganando y el candidato se elimina.
4. Después de `active -> old`: el rollback válido se restaura; solo si resulta
   inválido puede ganar un candidato completamente válido.
5. Después de `new -> active`: el nuevo activo válido gana y se limpia el
   rollback.
6. Antes de limpiar `/blocklist.old`: el nuevo activo válido gana y el rollback
   residual se elimina.

Los tests host/modelo y la inspección estática no demuestran la atomicidad real
de LittleFS ante pérdida de alimentación. Quedan pendientes HIL con cortes
controlados en cada frontera, reinicio posterior, verificación DNS de la lista
recuperada y confirmación de que un estado sin copia válida permanece
fail-closed sin STA, portal, DNS ni panel. Ese estado no puede repararse desde la
red: exige restaurar por USB una imagen LittleFS conocida y validada, con
aprobación humana separada. Tampoco se considera resuelta la autenticidad de una
lista subida manualmente ni la confidencialidad del panel HTTP.

El gate temprano de `Content-Length` se aplica al cuerpo multipart completo con
4.096 bytes de margen sobre el máximo de archivo, mientras el límite por chunks
de 524.285 bytes es el control definitivo. Un filename o framing multipart
inusualmente grande puede producir un 413 conservador aun con un archivo de
tamaño válido. Además, `WebServer` procesa multipart de forma síncrona: los
guards de partes adicionales y la limpieza de una transacción huérfana son
invariantes estáticos/modelados, no una prueba HTTP real. Quedan pendientes un
cliente lento, desconexión a mitad de body, multipart sin fichero/con varias
partes, timeout del core, recuperación del loop/DNS y rate limiting general.

La validación local integrada de P5.3a terminó con **163 passed** y Ruff sin
errores. PlatformIO terminó `SUCCESS`: RAM estática 50.684/327.680 B (15,5 %),
flash enlazada 1.122.703/1.376.256 B (81,6 %) y margen enlazado 253.553 B.
`firmware.bin` mide 1.160.704 B, deja 215.552 B físicos y tiene SHA-256
`D1A24F2D579D6B1617850B07E6FA2A403CBF90E08DDD5DD033475D33B7C34F2C`. Frente a
P5.2a son −648 B de RAM, −127.858 B enlazados y −131.568 B físicos. El build
emitió tres warnings porque, sin Internet, omitió la comprobación remota de
dependencias; no fueron errores de compilación. `ci_checks repository`, ambos
diff checks y el gate de archivos protegidos pasan localmente. La CI real y todo
HIL P5.3a siguen pendientes.

## P5.4 — reintento STA acotado

P5.4 conserva el preflight STA y el workaround RF validados, pero evita caer al
portal de provisioning tras un único plazo de asociación transitorio. Antes de
cualquier inicialización Wi-Fi, tanto en el camino STA como en el portal por
ausencia de verificador administrativo, configura una sola vez
`WiFi.persistent(false)`. Esta llamada selecciona almacenamiento RAM para la
configuración interna del core Arduino durante el boot; no borra ni reescribe
las credenciales de aplicación guardadas en Preferences.

Los gates automatizados de esta entrega deben cubrir:

- preflight ejecutado una sola vez y en el orden existente:
  `WiFi.mode(WIFI_STA)`, `WiFi.setSleep(false)`, espera acotada de
  `WiFi.STA.started()` y `applyC3RfWorkaround()`;
- una sola llamada con credenciales a `WiFi.begin(ssid, pass)` y limpieza
  inmediata de la copia local de la contraseña;
- primera ventana de asociación de 20.000 ms y retorno inmediato sin reconnect
  cuando alcanza `WL_CONNECTED`;
- tras el primer timeout, un `WiFi.disconnect(false, false, 100)` comprobado,
  espera de 250 ms y como máximo una llamada a `WiFi.reconnect()`;
- fallo del primer disconnect sin reconnect, y fallo de `WiFi.reconnect()` sin
  abrir una segunda ventana;
- si reconnect arranca, una sola segunda ventana de 20.000 ms; su timeout hace
  un disconnect final comprobado, espera 250 ms y devuelve el control al mismo
  fallback de portal;
- constantes explícitas `WIFI_ASSOCIATION_TIMEOUT_MS = 20000`,
  `WIFI_DISCONNECT_TIMEOUT_MS = 100` y `WIFI_RETRY_SETTLE_MS = 250`, con
  resta wrap-safe de `millis()`;
- máximo de dos ventanas, ausencia de recursión o bucles de reconnect no
  acotados y conteos máximos de un `WiFi.begin` y un `WiFi.reconnect`;
- ausencia de retry cuando faltan credenciales o fallan modo STA, arranque STA o
  workaround RF;
- ausencia de nuevas escrituras persistentes, logging de credenciales, eventos
  Wi-Fi, política por reason code, reinicio o ciclo adicional de `WIFI_STA`;
- invariantes de BOOT, autenticación, blocklist, OTA ausente y archivos
  protegidos sin cambios.

El peor caso configurado de la secuencia de asociación es 40.700 ms: dos
ventanas de 20.000 ms, dos timeouts de disconnect de hasta 100 ms y dos esperas
de 250 ms. A esto se suma la espera preexistente de hasta 1.000 ms para que STA
arranque y el pequeño overshoot del polling. El core Arduino puede efectuar
reintentos internos durante cada ventana; P5.4 acota las acciones adicionales de
la aplicación, no el número de tramas RF internas.

La validación local pasa con 173 tests, Ruff, `ci_checks repository`, ambos diff
checks, archivos protegidos y build PlatformIO. El build usa 50.684 bytes de RAM
y 1.123.177 bytes de flash enlazada; `firmware.bin` mide 1.161.360 bytes, deja
214.896 bytes físicos y tiene SHA-256
`81BD51E0582A34F206CC08FB4A2F8643DC3999062B4C611B67AE0831C7226A97`.

Quedan pendientes la CI real y el HIL específico: conexión en la primera
ventana; hotspot disponible solo durante la segunda; dos timeouts con aparición
del mismo portal; reinicio posterior sin reprovisioning; y regresión de BOOT,
login, dashboard, DNS permitido/bloqueado y upload manual. Hasta entonces P5.4
no acredita hardware ni autoriza PILOT.

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

- ejecución real de P5.3a en GitHub y confirmación humana de ambos jobs para su
  revisión exacta;
- decidir si los checks serán obligatorios mediante branch protection;
- mantener pruebas de Windows 10 real, hardware, red, DNS y panel ya enumeradas.

Las ejecuciones verdes confirmadas de `dce4672` y `bbeacda` validan únicamente
esas revisiones. La inspección estructural o el parseo local del YAML tampoco
acreditan P5.3a.

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

## Hardware — baseline confirmada y trabajo pendiente

Una persona confirmó el HIL completo solicitado de P5.2/P5.2a sobre `bbeacda`,
incluidos auth/sesión/CSRF/Host/XSS, portal físico BOOT y recuperación runtime.
Esa confirmación no incluye P5.3a. Para P5.3a quedan pendientes upload manual
real, respuestas HTTP, multipart/abort/desconexión, presión de espacio y los seis
cortes de alimentación de la matriz anterior. También siguen pendientes:

- 24 horas y 7 días;
- varios clientes;
- reinicio router;
- cambio Wi-Fi.

La baseline `dce4672` completó HIL end-to-end con alimentación independiente,
SoftAP/DHCP/portal, STA, dashboard y DNS. `bbeacda` añadió la confirmación HIL
completa de P5.2/P5.2a; ninguna de ellas sustituye el HIL nuevo de P5.3a.

## Piloto mínimo — pendiente

- cero reinicios inesperados en 7 días;
- cero secretos;
- recuperación documentada;
- panel protegido;
- versión identificable;
- limitaciones entregadas.
