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
  el servidor HTTP podría registrar cuerpos de formularios sensibles;
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
- dispatcher por `Content-Type`: `/upload` acepta exclusivamente
  `application/octet-stream` con `[blocklist.sig raw de 128 bytes][blocklist.bin]`;
  otros cuerpos se rechazan con 415 sin crear candidato;
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

El gate temprano exige un `Content-Length` estricto e igual al tamaño que
`esp_http_server` ya ha parseado. El total máximo es 524.413 bytes: los 128 de
`blocklist.sig` más 524.285 bytes de `blocklist.bin`. La longitud firmada debe
coincidir exactamente con el resto del cuerpo antes de abrir staging. El reader
streaming tiene buffer de 512 bytes, límite absoluto de 30 segundos y no acepta
bytes de cuerpo fuera de esa longitud autenticada. Quedan pendientes HIL de
cliente lento, desconexión a mitad de body, matriz de framing HTTP crudo,
recuperación del loop/DNS y rate limiting general.

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

## P5.5 — procedencia firmada de blocklists manuales

P5.5 mantiene intacto el formato activo de registros de cinco bytes y exige para
cada nuevo upload HTTP una prueba de 128 bytes. En P6.2 el navegador envía un
cuerpo `application/octet-stream` fijo: `blocklist.sig` raw (bytes 0..127)
seguido de `blocklist.bin`. El firmware valida el envelope y ECDSA P-256/SHA-256
antes de abrir `/blocklist.new`, exige que el resto del cuerpo tenga exactamente
la longitud firmada y vuelve a comprobar tamaño, recuento y SHA-256 contra los
bytes persistidos antes y después de promocionarlos.

Los tests permanentes de esta entrega cubren:

- layout exacto del manifest/proof, dominio firmado, little-endian y tabla de
  confianza con una única clave pública de producción, Key ID `2173599637` y
  List ID `1`;
- firma válida y rechazos por firma o payload alterados, proof truncado/hex
  malformado, clave desconocida, list ID, versión, algoritmo, flags, secuencia
  cero, longitud, count, SHA y valores `r`/`s` inválidos;
- rechazo antes de crear staging cuando falla el proof y rechazo de una
  blocklist estructuralmente válida pero no autorizada;
- promoción autenticada y rollback, recuperación candidate-only solo con
  `/blocklist.new.auth`, rechazo permanente de un candidato unsigned y
  compatibilidad de boot con active/old legacy unsigned;
- modelo de cada frontera de corte: escritura del candidato, persistencia del
  proof, `active -> old`, `new -> active`, revalidación, retirada del proof y
  retirada final del rollback;
- UI de dos ficheros, firma exacta de 128 bytes y envelope binario fijo
  `[blocklist.sig][blocklist.bin]`; guards Host/sesión/CSRF y POST anteriores
  permanecen obligatorios;
- signer genérico: validación del blob, manifest de 64 bytes, digest de
  protocolo, P-256, `r || s` fijo con low-S y sustitución atómica;
- ausencia de clave privada, fetch remoto y OTA, además de todas las regresiones
  P5.1–P5.4 y los archivos protegidos.

Las fixtures son locales y offline. Incluyen un vector público SigVer
P-256/SHA-256 de NIST y un vector de protocolo creado con una clave desechable
TEST-ONLY fuera del repositorio. Solo quedan payload, proof y clave pública; la
clave privada temporal fue destruida y la clave pública de test no aparece en la
tabla de confianza del firmware. La procedencia y el SHA-256 del paquete NIST se
registran junto a las fixtures. Ningún test firma con la clave de producción.

La cobertura host modela la secuencia de filesystem, pero no demuestra la
durabilidad ni atomicidad real de LittleFS. Quedan pendientes HIL del envelope
binario real, framing HTTP crudo y cortes controlados en cada frontera. V1 acepta deliberadamente replay de
una release correctamente firmada y conserva compatibilidad de boot con listas
legacy unsigned; tampoco guarda un proof activo permanente, por lo que aporta
procedencia de ingreso, no attestation continua en reposo.

La validación local integrada termina con **231 passed**, Ruff y ambos diff
checks correctos, `ci_checks repository` verde y archivos protegidos intactos.
PlatformIO termina `SUCCESS`: 50.828/327.680 B de RAM (15,5 %),
1.127.265/1.376.256 B de flash enlazada (81,9 %) y 248.991 B de margen enlazado.
`firmware.bin` mide 1.165.808 B, deja 210.448 B físicos (205,52 KiB) y tiene
SHA-256 `67DFDE5BE7A11D608B624AA3C8E1DD56896696986B0CD8EB1BF6A0DE699814B7`.
Frente a P5.4 son +144 B RAM, +4.088 B enlazados y +4.448 B físicos. La CI real
y todo HIL P5.5 siguen pendientes.

## P6.2 — envelope binario y límites de transacción

Los gates permanentes cubren el cuerpo `application/octet-stream` con proof raw
de 128 bytes seguido por el payload firmado, sin multipart ni proof en cabecera.
El harness nativo `test_fixed_envelope.cpp` prueba fragmentación de cada posición
del prefijo, prefetch sobre la frontera proof/payload, truncado, EOF, timeout,
error de receive, trailing byte y límites exactos de 524.285 B. El harness
`test_admin_state.cpp` prueba los límites de ventana: no hay trabajo nuevo desde
300.000 ms, un upload aceptado puede continuar hasta `min(upload+30 s, ventana+330 s)`,
y una promoción fallida no consume su único cupo exitoso.

La recuperación llama la limpieza proof-first de `.new.auth` y después `.new`
solo tras clasificar active/old/candidate; no borra el active. El HIL de framing
HTTP crudo confirmó: `Content-Length` duplicado igual o conflictivo se rechaza
antes del handler; `Content-Length`+`Transfer-Encoding` (ambos órdenes) y
`Transfer-Encoding` duplicado probado se reinician/rechazan antes del handler;
`Transfer-Encoding: chunked` aislado llega al handler con `content_len=0` y valor
visible `chunked`. Por diseño, `/upload` rechaza cualquier `Transfer-Encoding`
visible antes de leer el envelope o abrir staging. Los bytes posteriores a un
`Content-Length` no pasan a ser el cuerpo de la petición actual y un cuerpo
ordinario fragmentado se recibe completo. Siguen pendientes HIL de
LittleFS/power-loss, cliente lento y disponibilidad DNS.

## P6.1 — parser DNS acotado y correlación upstream

P6.1 separa la lógica pura de protocolo en `src/dns_protocol.cpp` para que el
firmware y el harness nativo ejecuten exactamente el mismo parser y las mismas
reglas de correlación. El transporte sigue siendo UDP, síncrono y con una sola
consulta upstream pendiente; no se añade tabla asíncrona, DNS-over-TLS,
DNS-over-HTTPS ni un cambio de resolver.

Los gates permanentes de esta entrega cubren:

- datagramas cliente y upstream limitados a 600 bytes, sin lecturas parciales
  que dejen bloqueado el `rx_buffer` de `NetworkUDP`;
- header de query, una única pregunta, labels y longitud total acotados, root
  terminator presente y rechazo explícito de compression pointers en la
  pregunta;
- respuestas truncadas o malformadas y diferencias de QR, opcode, QDCOUNT,
  transaction ID, QNAME, QTYPE o QCLASS;
- origen UDP exactamente igual al upstream configurado y puerto remoto 53,
  comprobados inmediatamente después de `parsePacket()`;
- transaction ID upstream generado por el dispositivo y restauración del ID del
  cliente solamente después de validar la respuesta completa;
- drenaje acotado de datagramas anteriores, máximo acotado de candidatos durante
  la espera y timeout wrap-safe de 1.000 ms;
- comprobación de `beginPacket()`, `write()` y `endPacket()`, limpieza de cada
  datagrama rechazado y ausencia de forward para queries inválidas o bloqueadas;
- conservación del modelo síncrono, cediendo el loop después de una consulta
  permitida para no encadenar hasta 16 esperas upstream;
- corpus determinista para respuesta válida, origen/puerto/ID/pregunta
  incorrectos, query truncada, label de 64 bytes, terminador ausente,
  compression pointers, stale antes de válida, múltiples candidatos falsos y
  timeout;
- mutaciones deterministas de longitudes y bytes, sin dependencias nuevas ni
  tráfico de red.

`tests/test_p6_1_dns.py` compila en Windows el código de producción junto a
`tests/native/test_dns_protocol.cpp` y ejecuta el corpus más 100.000 mutaciones
con AddressSanitizer. El job Linux `dns-native-sanitizers` compila esos mismos
dos ficheros con ASan y UBSan, y ejecuta 1.000.000 de mutaciones con seed fija
`0x4E534D`. La presencia del job en YAML no demuestra que GitHub Actions haya
pasado: la ejecución real de los tres jobs y su confirmación humana siguen
pendientes.

También queda pendiente HIL con un upstream UDP controlado: respuesta correcta,
origen/puerto/ID/pregunta falsos antes de la correcta, respuesta tardía tras
timeout, caída de upstream, ráfaga hostil, A/AAAA permitidos y consultas
bloqueadas sin tráfico upstream. Debe registrarse además que dashboard y BOOT
siguen respondiendo durante fallos DNS. Hasta esa evidencia, TM-22 y TM-23 son
como máximo candidatas a `MITIGATED`, no `CLOSED`.

Validación local P6.1: la suite completa termina con 246 tests aprobados. El gate
pytest ejecuta 100.000 mutaciones bajo MSVC ASan; una ejecución adicional de
release completó 1.000.000, seed `0x4E534D`, 2.000.169 checks y checksum
`0x6EC04F`, sin findings. Ruff, los checks de diff, `ci_checks` y los archivos
protegidos pasan. El build PlatformIO termina `SUCCESS`: RAM 51.420 B, flash
enlazada 1.129.779 B, `firmware.bin` 1.168.720 B, margen físico 207.536 B y
SHA-256 `EE75C250AE7BA1D922FF6F448AB2A360E62872E34F044EB2951625544C565BB8`.
La ejecución Linux ASan/UBSan y todo HIL P6.1 siguen pendientes.

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

P6.1 añade el job Linux `dns-native-sanitizers`, sin credenciales, servicios ni
descargas de datos. Reutiliza el checkout fijado por SHA, usa el `g++` incluido
en `ubuntu-24.04` y compila directamente `src/dns_protocol.cpp` con
`tests/native/test_dns_protocol.cpp`. El ejecutable se construye con
AddressSanitizer y UndefinedBehaviorSanitizer y procesa un corpus determinista
más 1.000.000 de mutaciones con seed `0x4E534D`. El job no sustituye el build
PlatformIO ni el HIL de sockets UDP reales.

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

- ejecución real de P6.1 en GitHub y confirmación humana de los tres jobs para su
  revisión exacta, incluido ASan/UBSan Linux;
- decidir si los checks serán obligatorios mediante branch protection;
- mantener pruebas de Windows 10 real, hardware, red, DNS y panel ya enumeradas.

Las ejecuciones verdes confirmadas de revisiones anteriores validan únicamente
sus commits exactos. La inspección estructural o el parseo local del YAML no
acreditan P6.1 ni sustituye su ejecución en GitHub.

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

## DNS — implementado parcialmente en P6.1

- parser y correlación P6.1 cubiertos por corpus nativo y mutaciones
  deterministas bajo sanitizers;
- A y AAAA conservan el comportamiento previo en los gates host; falta su HIL;
- se admite un único OPT EDNS0 acotado; compression pointers en questions y
  múltiples preguntas se rechazan, QTYPE 0 es inválido y los demás QTYPE no
  cero se reenvían;
- quedan pendientes DNS sobre TCP, DNSSEC, respuestas mayores de 600 bytes,
  compatibilidad amplia de EDNS y fuzzing continuo/coverage-guided.

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
real, respuestas HTTP, envelope binario/abort/desconexión, presión de espacio y los seis
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
