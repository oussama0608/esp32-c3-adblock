# Política de seguridad

## Estado actual

NetShield Mini está en desarrollo y **todavía no se considera seguro para un
piloto ni para un despliegue doméstico**. No existe una versión de producción
con soporte de seguridad. La clasificación de diseño permanece en cinco
amenazas CRITICAL, veinte HIGH y cinco MEDIUM. P5.1 mantiene TM-07, TM-09,
TM-26 y TM-27 en `MITIGATED`, no `CLOSED`. P5.2/P5.2a reducen de forma directa
TM-01, TM-02 y TM-16 a TM-19. Están committed y pushed en `bbeacda`; una persona
confirmó ambos jobs de CI verdes y el HIL completo solicitado, pero las amenazas
no se cierran mientras el panel continúe sobre HTTP claro. El registro, los tests y las
condiciones de aceptación están en
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

P1 recuperó el build reproducible, P2 endureció y probó el generador host, P3
añadió CI y P5.1 retiró las dos vías OTA de firmware por red. P5.1 está
committed en `dce4672`; una persona confirmó verdes sus jobs `python-quality` y
`firmware-build`, y el HIL end-to-end validó SoftAP/DHCP/portal, persistencia,
STA, panel y DNS. La limitación de potencia a 8,5 dBm queda documentada como un
workaround observado en la ESP32-C3 SuperMini probada, no como requisito de
todos los ESP32-C3. P5.2/P5.2a están confirmados únicamente para `bbeacda`; esa
evidencia no se extrapola a entregas posteriores. Los demás controles de
seguridad del dispositivo siguen pendientes. P5.3a deshabilita el fetch remoto de
blocklists y convierte el upload manual en un reemplazo recuperable. P5.5 exige
procedencia firmada a cada nuevo upload, pero no autentica permanentemente las
listas legacy/en reposo ni convierte el dispositivo en apto para piloto.

No se debe flashear la candidate P5.5 a una unidad piloto ni convertirla en DNS
de una red real. Cualquier nuevo flash de laboratorio queda condicionado a sus
gates, a [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) y a otra aprobación humana
explícita.

## Activos protegidos

- credenciales y asociación Wi-Fi;
- firmware, arranque y recuperación física;
- configuración DNS, blocklist, bans y dominios personalizados;
- disponibilidad y corrección del servicio DNS;
- privacidad de consultas, IP, MAC y actividad de clientes;
- control administrativo, flash y heap del dispositivo.

## Cinco bloqueantes principales

1. P5.2/P5.2a ya superaron el HIL acordado de panel y recovery BOOT, pero el
   panel sigue sobre HTTP claro y una exposición WAN agravaría el impacto.
2. P5.5 autentica la procedencia de nuevos uploads y mantiene el rollback de
   P5.3a, pero todavía permite replay, conserva listas legacy unsigned y necesita
   HIL de multipart y corte de alimentación sobre LittleFS.
3. P5.2 sustituye los sinks DOM peligrosos, separa JavaScript y aplica escape
   contextual; el HIL funcional no sustituye un corpus XSS adversarial completo.
4. El parser DNS, la asociación upstream, los límites de tasa y el heap no tienen
   todavía fuzzing, carga sostenida ni HIL adversarial.
5. La procedencia, firma y anti-downgrade del firmware USB no están resueltos;
   quedan binarios legacy y la restauración de LittleFS/power-loss no tiene HIL.

## Estado de P5.1

P5.1 está committed en `dce4672`, con validación local, ambos jobs de CI verdes
confirmados por una persona y HIL funcional end-to-end:

- `/update`, sus handlers y el formulario/JavaScript del panel fueron retirados;
- ArduinoOTA fue eliminado del código, dependencias enlazadas, ELF/map y binario;
- los dos installers activos son ahora avisos estáticos, y sus manifests son
  marcadores inertes con `builds: []`;
- los binarios anteriores permanecen sin cambios, únicamente como artefactos
  legacy de auditoría, y no se generó ni publicó un reemplazo;
- `partitions.csv` y sus dos slots no cambiaron;
- la recuperación USB está documentada en
  [docs/USB_RECOVERY_WINDOWS.md](docs/USB_RECOVERY_WINDOWS.md); cualquier prueba
  destructiva específica de recovery sigue requiriendo autorización separada.

La clean candidate de `dce4672` mide 1.274.960 bytes físicos, enlaza 1.234.851
bytes y usa 51.164 bytes de RAM estática. Quedan 101.296 bytes físicos en el
slot. P5.3a conserva únicamente el upload manual y retira el fetch remoto; el
upload permanece fuera de PILOT hasta validar autenticidad, límites y recovery
real ante cortes.

El orden completo P5.1-P5.10 y la comparación A-E están registrados en
`docs/THREAT_MODEL.md`. La entrega P5.2 combinó los controles de panel
que ADR-004 había separado entre P5.2, P5.3 y P5.4; no adelanta los parches de
integridad de blocklist, TLS/SSRF, DNS o filesystem.

## Diseño de la candidate P5.2

- Una contraseña administrativa local de 12 a 128 bytes crea un verificador
  PBKDF2-HMAC-SHA-256 de 32 bytes con 50.000 iteraciones y salt aleatorio de 16
  bytes. NVS guarda solo versión, iteraciones, salt y verificador; no guarda la
  contraseña.
- El alta o restablecimiento de la contraseña falla cerrado y exige mantener
  BOOT tres segundos con el portal y el firmware ya en ejecución. La recuperación
  desde STA exige cinco segundos, invalida sesión/CSRF, borra Wi-Fi/verificador y
  reinicia solo después de soltar BOOT. No existe contraseña por defecto ni
  recuperación remota; BOOT durante reset/power-on pertenece únicamente al
  downloader ROM y nunca es el gesto de provisioning.
- Una única sesión y su token CSRF se generan con el RNG del ESP, viven solo en
  RAM y expiran a los 30 minutos. La cookie usa `HttpOnly`, `SameSite=Strict` y
  `Path=/`; no usa `Secure` porque el dispositivo sigue siendo HTTP-only, lo que
  se mantiene como riesgo explícito.
- Login aplica un throttle creciente y acotado, solo en RAM. Las mutaciones son
  POST y exigen sesión más CSRF; logout, expiración y reboot invalidan la sesión.
- El panel acepta como `Host` únicamente su IPv4 actual o
  `c3adblock.local`, con el sufijo opcional `:80`. Los demás valores se rechazan
  antes de servir datos administrativos.
- HTML/JSON se codifican por contexto, el dashboard evita construir contenido no
  confiable mediante HTML ejecutable y las respuestas llevan headers ligeros de
  no-cache, MIME, referrer y CSP.
- En la baseline P5.2, `/upload`, `/fetchnow` y `/setupdate` quedaron detrás de
  estos controles de acceso. P5.3a conserva `/upload` y elimina las dos rutas
  remotas; P5.5 exige además una firma autorizada para cada nuevo upload.

## Diseño de la candidate P5.3a

- No existe actualización remota de blocklist: `/fetchnow`, `/setupdate`, URL,
  intervalo, scheduler, clientes HTTP/TLS y controles de UI quedan compilados
  fuera. Un `/update.cfg` legacy queda inerte: no se abre, interpreta ni usa para
  volver a habilitar fetch, pero puede conservar físicamente una URL o token
  histórico y ocupar LittleFS hasta una restauración explícita.
- El panel conserva el upload manual autenticado con CSRF e informa: «Las
  actualizaciones remotas de listas están desactivadas en esta versión. Usa
  únicamente archivos de blocklist validados.»
- `/blocklist.new` se cierra y valida antes de sustituir `/blocklist.bin`.
  `/blocklist.old` mantiene la última copia válida durante el reemplazo. El
  límite de nuevos candidatos es 104.857 registros o 524.285 bytes. Una lista
  activa legacy válida puede seguir leyéndose, pero nunca se borra para liberar
  espacio: el upload se rechaza si no puede coexistir con ella.
- Al arrancar, un activo válido tiene precedencia; sin él se restaura un rollback
  válido y, solo si tampoco existe, se promueve un candidato válido. Sin ninguna
  copia válida, la carga falla cerrada antes de iniciar cualquier servicio de
  red. LittleFS no se autoformatea y los restos se limpian sin presentar una
  lista vacía como actualización correcta. Recuperar ese estado exige USB y una
  imagen LittleFS conocida y validada, bajo aprobación humana separada.
- Esta secuencia reduce TM-06/TM-13 y compila fuera la superficie de TM-08,
  TM-14 y TM-15 asociada al fetch. Las amenazas no se consideran cerradas sin CI
  confirmada y HIL de cortes. En P5.3a el upload aún no verificaba firma o
  procedencia; P5.5 añade ese gate de ingreso sin convertir las listas legacy en
  contenido autenticado en reposo.
- En P6.2 el transporte de upload es exclusivamente `application/octet-stream`:
  los bytes 0..127 son el `blocklist.sig` raw y el resto debe coincidir exactamente
  con el `blocklist.bin` autenticado. El total máximo es 524.413 B; el payload
  sigue limitado a 524.285 B. Cualquier otro media type o longitud se rechaza
  antes de abrir staging. El reader es streaming y acotado. HIL real verificó que
  `esp_http_server` rechaza antes del handler `Content-Length` duplicado (igual o
  conflictivo), `Content-Length`+`Transfer-Encoding` y los dos órdenes de
  `Transfer-Encoding` duplicado. Un `Transfer-Encoding: chunked` aislado sí llega
  con `content_len=0`; por ello `/upload` rechaza explícitamente cualquier
  `Transfer-Encoding` visible antes de consumir el slot, leer el envelope o abrir
  staging. Siguen pendientes HIL de cliente lento, LittleFS/power-loss y
  disponibilidad DNS.

La validación local P5.3a termina con 163 tests y Ruff correctos. PlatformIO
termina `SUCCESS` con 50.684 B de RAM, 1.122.703 B de flash enlazada y un
`firmware.bin` de 1.160.704 B; quedan 215.552 B físicos y el SHA-256 es
`D1A24F2D579D6B1617850B07E6FA2A403CBF90E08DDD5DD033475D33B7C34F2C`. Los tres
warnings corresponden a la comprobación remota de dependencias omitida por falta
de Internet. `ci_checks repository`, los diff checks y el gate de archivos
protegidos pasan localmente; CI real y HIL P5.3a siguen pendientes. No se
autoriza flash ni piloto.

## Diseño de la candidate P5.5

- El firmware confía en una sola clave pública P-256 aprobada, con Key ID
  `2008216462`, y acepta exclusivamente List ID `1`. La clave privada de
  producción no existe en firmware, repositorio, tests ni CI.
- P7 sustituyó el trust anchor anterior de Key ID `2173599637` porque su
  passphrase dejó de estar disponible. La rotación conserva el protocolo, pero
  las firmas emitidas por la clave retirada son intencionadamente inválidas para
  este firmware; las blocklists activas legacy siguen siendo compatibles al boot.
- La blocklist activa no cambia de formato. El proof separado tiene 128 bytes y
  firma con ECDSA P-256/SHA-256 el manifest que contiene secuencia no nula,
  longitud, recuento y SHA-256 del payload. La UI exige ambos ficheros y envía
  un único cuerpo `application/octet-stream`: los 128 bytes raw de `blocklist.sig`
  seguidos exactamente por `blocklist.bin`; no se acepta proof en cabeceras.
- Host, sesión y CSRF se comprueban antes de leer el proof. Un prefijo ausente,
  malformado, no autorizado o con firma inválida se rechaza antes de abrir
  `/blocklist.new`. El candidato persistido se valida y autentica otra vez antes
  y después de la promoción; los fallos conservan o restauran el last-known-good.
- `/blocklist.new.auth` existe solo durante staging/promoción. El proof se elimina
  antes que el candidato al descartar, permanece durante los dos renames y se
  elimina mientras `/blocklist.old` aún permite rollback. Un candidate-only sin
  proof válido nunca se recupera al arrancar.
- Las listas active/old legacy unsigned siguen siendo boot-compatibles sin
  migración escrita. P5.5 V1 permite deliberadamente replay de releases firmadas
  anteriores, no guarda un sidecar activo ni añade anti-replay/NVS: es procedencia
  de ingreso, no attestation permanente en reposo.
- El signer host acepta la ruta de una clave P-256 por CLI, valida el blob,
  construye el manifest exacto, exporta `r || s` fijo/low-S y escribe el proof
  atómicamente. No incorpora, solicita ni imprime la clave privada de producción.
- Fetch remoto y firmware OTA permanecen ausentes. El panel sigue sobre HTTP
  claro; CI real, HIL de framing/envelope, fallos de LittleFS y cortes en cada frontera
  siguen pendientes. Por ello P5.5 continúa **DEVELOPMENT-only** y PILOT es
  **NO-GO**.

La validación local P5.5 pasa 231 tests, Ruff, `ci_checks repository`, ambos diff
checks y el gate de archivos protegidos. El build PlatformIO termina `SUCCESS`
con 50.828 B de RAM y 1.127.265 B de flash enlazada. `firmware.bin` mide
1.165.808 B, deja 210.448 B físicos y tiene SHA-256
`67DFDE5BE7A11D608B624AA3C8E1DD56896696986B0CD8EB1BF6A0DE699814B7`.
Estas pruebas locales no equivalen a CI ejecutada en GitHub ni a HIL.

## Perfiles permitidos

### DEVELOPMENT

Solo para nuestra placa y LAN aislada de pruebas, sin tráfico personal, sin
administración WAN y sin configurarlo como DNS de una red real. OTA de firmware
está compilada fuera. La candidate actual solo puede probarse con contraseña y
SSID de laboratorio no sensibles y sin capturar secretos por Serial. El canal
HTTP, el portal físico abierto y los controles aún pendientes
impiden tratar esta configuración como un piloto. Flasheo y puerto serie
requieren aprobaciones separadas.

### PILOT

No está permitido todavía. Requiere cero amenazas CRITICAL abiertas, todos los
HIGH corregidos o aceptados expresamente con control compensatorio, capacidades
inseguras compiladas fuera, CI real confirmada, fuzzing y HIL, recuperación por
BOOT/USB, pruebas de corte, carga y soak, y política de privacidad/soporte. OTA
de firmware seguirá ausente salvo una decisión posterior con firma y
anti-downgrade. El panel administrativo permanece ausente/read-only salvo que un
canal proteja credencial y sesión; añadir password sobre HTTP claro no basta.

## Invariantes obligatorios

- No guardar SSID, claves, tokens ni credenciales reales en Git, tests o logs.
- No administrar desde Internet ni configurar UPnP, port-forward, DMZ o cloud.
- No usar HTTP remoto ni `setInsecure()` como solución final.
- No activar portal cautivo salvo onboarding o recuperación física temporal.
- No borrar una blocklist válida antes de validar y confirmar su reemplazo.
- No autoformatear un filesystem corrupto ni anunciar un fallo como éxito.
- No aceptar firmware o blocklists sin límites, procedencia y recovery definidos.
- No servir un binario stale ni cargar tooling móvil de un CDN sin pin/SRI o
  vendoring; manifest, hash y fuente deben corresponder.
- No reenviar DNS malformado ni aceptar una respuesta upstream no asociada.
- No conservar historial de dominios ni introducir telemetría por defecto.
- No modificar particiones, eFuses, secure boot o flash encryption sin cálculo,
  plan de recuperación y aprobación humana.
- No afirmar bloqueo total, anonimato, antivirus ni seguridad ya alcanzada.

## Datos y privacidad

La política objetivo es no persistir QNAME ni historial de navegación, no enviar
telemetría y no depender de cloud. Solo se admiten contadores agregados y datos
operativos mínimos con TTL documentado. IP/MAC, URLs y SSID se tratan como datos
sensibles; no deben mostrarse a clientes anónimos ni aparecer completos en logs.
Debe existir un borrado físico verificable de configuración. Las consultas
permitidas hoy salen por UDP claro a Quad9 y son visibles para el resolver y
observadores on-path; esta limitación debe comunicarse y no equivale a privacidad
de transporte.

## Comunicación de vulnerabilidades

No publiques credenciales, datos de usuarios, firmware malicioso funcional ni
detalles explotables que afecten a una unidad desplegada. Si el repositorio
muestra la opción privada **Report a vulnerability**, úsala. Si no existe un
canal privado configurado, contacta primero con el mantenedor sin incluir el
secreto o payload en una issue pública. Las incidencias no sensibles sí pueden
describirse con una reproducción mínima, versión/commit, impacto y resultado
esperado.

Una respuesta o corrección documental no implica que el firmware sea seguro. La
amenaza solo se cierra cuando su test y condición de aceptación pasan en el
perfil afectado.
