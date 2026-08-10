# Modelo de amenazas y plan de hardening

## Estado y alcance

- Fecha de análisis original: 2026-08-07; actualización P5.2: 2026-08-08.
- Baseline P4 revisada: `develop` en `c1ad780`, después de P1, P2 y P3.
- Baseline de implementación P5.2: `develop` en `dce4672`, después de P5.1.
- Hardware objetivo: ESP32-C3 SuperMini, 4 MB flash, sin PSRAM.
- Alcance: firmware, panel HTTP, onboarding Wi-Fi, DNS, persistencia y
  actualización. La cadena de build de P1-P3 se usa como control de desarrollo,
  no como prueba de seguridad del dispositivo.
- Fuera de alcance de P4: implementar controles, flashear, usar puertos serie,
  cambiar la red o las particiones y habilitar un despliegue.

Este documento describe el estado actual, no un estado seguro. El firmware no
está preparado para un piloto. Una persona confirmó verdes los jobs
`python-quality` y `firmware-build` de `dce4672`; esa evidencia pertenece solo a
ese commit y no acredita la candidate P5.2 hasta ejecutar su revisión exacta.

La imagen local de referencia mide 1.298.656 bytes frente a un slot app de
1.376.256 bytes: quedan 77.600 bytes (75,78 KiB, 5,64 %) y la ocupación física
es 94,36 %. PlatformIO reportó además 1.254.885 bytes de flash y 53.124 bytes de
RAM estática. P4 no cambia ninguna de esas cifras porque solo modifica
documentación.

P5.1 está committed en `dce4672`, con CI verde confirmada y HIL funcional
end-to-end. Su clean candidate mide 1.274.960 bytes físicos, deja 101.296 bytes
en el slot, enlaza 1.234.851 bytes y usa 51.164 bytes de RAM estática. La
clasificación de severidad no cambia; el estado concreto de cuatro amenazas se
mantiene `MITIGATED` según la evidencia indicada abajo.

## Evidencia examinada

- `src/main.cpp`, incluido el inventario de rutas, persistencia, red y handlers;
- `src/page.h`, incluido el JavaScript que consume JSON y construye el DOM;
- `platformio.ini` y `partitions.csv` solo en lectura;
- `docs/UPSTREAM_AUDIT.md`, `docs/TEST_PLAN.md`, `docs/DECISIONS.md` y
  `SECURITY.md` completos;
- mapa y binario del último build local de P3.

Las citas de líneas conservadas dentro del registro detallado identifican la
baseline histórica P4 `c1ad780` y sus escenarios previos al control; no deben
usarse como localizadores de la candidate P5.2. Para el código actual, el
inventario de rutas de esta actualización y los nombres de handlers son la
referencia. Esta distinción evita presentar `HTTP_ANY`, `innerHTML`, `jesc` u
otras superficies históricas como si siguieran implementadas.

Los 47 tests pytest de P2 cubren el generador Python de blocklists y la baseline
completa anterior a P5.2 suma 67 resultados aprobados con los gates P5.1. P5.2
añade 32 gates estáticos y la suite local completa termina con 99 aprobados. P6.1
añade un harness C++ del parser/correlador DNS y mutaciones deterministas bajo
sanitizers; su CI real y HIL siguen pendientes. Tampoco hay todavía tests de
navegador para el panel P5.2. Sí existe HIL funcional end-to-end de `dce4672`.

## Método de clasificación

La probabilidad se expresa como:

- **Alta**: un atacante razonable puede provocar el escenario de forma directa
  en una LAN o durante onboarding, sin condiciones excepcionales.
- **Media**: requiere una condición adicional, temporización, interacción de la
  persona administradora o degradación previa.
- **Baja**: requiere acceso físico, una configuración externa errónea o una
  cadena poco frecuente.

La severidad combina impacto y explotabilidad:

- **CRITICAL**: ejecución persistente de firmware no confiable, pérdida total de
  control administrativo o exposición equivalente desde Internet.
- **HIGH**: pérdida importante de integridad, confidencialidad o disponibilidad
  DNS/Wi-Fi con un camino práctico de explotación.
- **MEDIUM**: exposición o degradación acotada, recuperable, o que requiere una
  condición fuerte adicional.
- **LOW**: defensa en profundidad con impacto bajo. No se ha rebajado ninguna de
  las amenazas actuales a esta categoría.

Una probabilidad baja no vuelve aceptable un impacto crítico. El perfil PILOT
no puede tener amenazas CRITICAL abiertas; cualquier HIGH residual exige un
control compensatorio, responsable y aceptación humana explícita.

## Activos y límites de confianza

Activos principales:

- firmware, partición de arranque y capacidad de recuperación;
- credenciales Wi-Fi y configuración persistente;
- blocklist, dominios personalizados y lista de clientes bloqueados;
- disponibilidad y corrección de las respuestas DNS;
- privacidad de IP, MAC, actividad y consultas de los clientes;
- control del panel y del portal cautivo;
- flash, heap, ciclos de CPU y vida útil del dispositivo.

Atacantes considerados:

- cliente no autenticado de la misma LAN;
- sitio web malicioso abierto por una persona de la LAN;
- equipo cercano durante onboarding mediante el AP del dispositivo;
- servidor, CDN, DNS o intermediario de red no confiable;
- cliente DNS que envía tráfico malformado o volumétrico;
- atacante de Internet si el router expone el dispositivo por error;
- persona con acceso físico breve o sostenido;
- fallos accidentales: corte de alimentación, filesystem lleno/corrupto o
  pérdida de Wi-Fi.

Flujos y límites:

1. Los clientes envían UDP/53 al ESP32; este analiza el nombre y, si permite la
   consulta, reenvía UDP/53 a `9.9.9.9`.
2. El navegador accede por HTTP/80 al panel y sus rutas administrativas.
3. En onboarding, un AP abierto, DNS cautivo y HTTP reciben SSID, password Wi-Fi
   y el alta local del verificador administrativo dentro de la ventana física.
4. NVS guarda credenciales; LittleFS guarda blocklist, bans y dominios. Un
   `/update.cfg` heredado puede seguir físicamente presente, pero P5.3a no lo
   abre ni interpreta.
5. P5.1 retiró la entrega de firmware por `/update` y ArduinoOTA. P5.3a conserva
   únicamente el upload manual autenticado de blocklist; no existe `HTTPClient`
   ni fetch remoto en el firmware de producción actual.
6. BOOT/GPIO9 es el límite físico de recuperación de credenciales Wi-Fi.

## Resumen del registro

| ID | Amenaza | Probabilidad | Severidad |
| --- | --- | --- | --- |
| TM-01 | Plano administrativo HTTP expuesto | Alta | HIGH |
| TM-02 | Exposición de `/stats.json` | Alta | MEDIUM |
| TM-03 | Manipulación y DoS mediante `/ban` | Alta | HIGH |
| TM-04 | Manipulación mediante `/addblock` y `/unblock` | Alta | HIGH |
| TM-05 | Borrado Wi-Fi mediante `/forgetwifi` | Alta | HIGH |
| TM-06 | Sustitución destructiva mediante `/upload` | Alta | HIGH |
| TM-07 | Firmware arbitrario mediante `/update` | Alta | CRITICAL |
| TM-08 | Fetch y configuración inseguros | Alta | HIGH |
| TM-09 | ArduinoOTA sin autenticación | Alta | CRITICAL |
| TM-10 | Portal cautivo abierto o activado por fallo | Alta | HIGH |
| TM-11 | Credenciales y estado en NVS | Media | MEDIUM |
| TM-12 | Autoformato con `LittleFS.begin(true)` | Media | HIGH |
| TM-13 | Blocklist no transaccional ni validada | Alta | HIGH |
| TM-14 | HTTP y TLS con `setInsecure()` | Media | HIGH |
| TM-15 | URLs configurables y SSRF | Alta | HIGH |
| TM-16 | XSS e inyección JSON/HTML | Alta | HIGH |
| TM-17 | CSRF en operaciones de estado | Alta | HIGH |
| TM-18 | Ausencia de autenticación y autorización | Alta | CRITICAL |
| TM-19 | DNS rebinding y falta de validación de `Host` | Media | HIGH |
| TM-20 | Ausencia de rate limiting | Alta | HIGH |
| TM-21 | Agotamiento y fragmentación de heap | Media | HIGH |
| TM-22 | Paquetes DNS malformados | Alta | HIGH |
| TM-23 | Respuestas upstream no asociadas | Media | HIGH |
| TM-24 | Pérdida de Wi-Fi sin recuperación controlada | Media | MEDIUM |
| TM-25 | Corrupción y corte durante persistencia | Media | HIGH |
| TM-26 | Firmware OTA malicioso o no auténtico | Alta | CRITICAL |
| TM-27 | Downgrade de firmware | Media | HIGH |
| TM-28 | Exposición accidental desde WAN | Baja | CRITICAL |
| TM-29 | Privacidad y retención de consultas | Media | MEDIUM |
| TM-30 | Recuperación física mediante BOOT | Baja | MEDIUM |

Totales: **5 CRITICAL, 20 HIGH, 5 MEDIUM y 0 LOW**.

Estado de baseline: las treinta amenazas están **OPEN**. Estados permitidos en
revisiones futuras: `OPEN`, `MITIGATED` (queda riesgo residual), `ACCEPTED`
(aceptación humana documentada) y `CLOSED` (test y aceptación cumplidos). Una
edición documental no cambia el estado; al cerrar o reclasificar una amenaza se
actualizarán simultáneamente el registro, los totales y la evidencia.

### Estado confirmado tras P5.1

| ID | Estado | Evidencia y riesgo residual |
| --- | --- | --- |
| TM-07 | MITIGATED | Ruta, handlers, librería y UI ausentes; CI verde confirmada. Falta el 404/405 explícito en HIL. |
| TM-09 | MITIGATED | API, dependencia, símbolos y strings ausentes; CI verde confirmada. Falta el escaneo explícito del servicio en HIL. |
| TM-26 | MITIGATED | Sin entrada de firmware por red y manifests inertes; firma/provenance USB y retirada remota siguen pendientes. |
| TM-27 | MITIGATED | Sin canal de downgrade por red; el recovery físico aún no valida versión ni anti-rollback. |

Estado agregado P5.1: **4 MITIGATED y 26 OPEN**. Las severidades de diseño siguen
siendo **5 CRITICAL, 20 HIGH, 5 MEDIUM y 0 LOW** hasta que sus condiciones de
aceptación completas permitan cierre o reclasificación. TM-18 y los riesgos de
blocklist, XSS, CSRF y DNS permanecen `OPEN`.

### Audit histórico de rutas y política P5.2

El portal cautivo y el servidor STA no se ejecutan simultáneamente, aunque ambos
reutilizan `WebServer`. `HTTP_ANY` describe el registro anterior a P5.2; la
columna final documenta la baseline P5.2, no el estado posterior P5.3a.

| Ruta | Método anterior | Propósito | ¿Muta? | Entrada/salida no confiable | Protección anterior | Acción P5.2 |
| --- | --- | --- | --- | --- | --- | --- |
| `/` (STA) | ANY | Dashboard | No | Muestra datos obtenidos de stats | Ninguna | GET; `Host` permitido y sesión; redirect fijo a `/login` si falta sesión; headers defensivos. |
| `/app.js` (STA) | No existía | Lógica propia del dashboard | No | Consume JSON y crea DOM | Script inline previo | GET; `Host` y sesión; recurso propio bajo CSP. |
| `/stats.json` | ANY | Estado, clientes y configuración | No | IP/MAC, custom domains, URL/estado | Same-origin solamente | GET; `Host` y sesión; JSON contextual y `no-store`. |
| `/ban` | ANY | Alternar ban de cliente | Sí | `ip` | Parseo de IP | POST; sesión y CSRF. La semántica toggle queda pendiente. |
| `/addblock` | ANY | Añadir dominio personalizado | Sí | `d` persistido/reflejado | Normalización mínima | POST; sesión y CSRF; salida segura. Validación DNS completa queda pendiente. |
| `/unblock` | ANY | Eliminar dominio personalizado | Sí | `d` | Normalización mínima | POST; sesión y CSRF; salida segura. |
| `/forgetwifi` | ANY | Borrar Wi-Fi y reiniciar | Sí | Sin body útil | Ninguna | POST; sesión y CSRF. Presencia física adicional sigue pendiente. |
| `/upload` | POST | Sustituir blocklist | Sí | Multipart/binario | Método y chequeo mínimo | POST; guard de sesión/CSRF también en upload y final. Swap seguro queda diferido. |
| `/fetchnow` | ANY | Descargar blocklist ahora | Sí | URL persistida | Ninguna | POST; sesión y CSRF. TLS/SSRF/atomicidad no cambian. |
| `/setupdate` | ANY | Guardar URL e intervalo | Sí | `u`, `h` | Mínimos de presencia/intervalo | POST; sesión y CSRF; render contextual. Validación/SSRF quedan pendientes. |
| `/login` | No existía | Mostrar/validar acceso local | Sí al crear sesión RAM | Password | Ninguna | GET/POST; allowlist de `Host`, respuesta genérica y throttle. |
| `/logout` | No existía | Invalidar sesión | Sí | Cookie y CSRF | Ninguna | POST; `Host`, sesión y CSRF; borra token RAM/cookie. |
| `/` (portal) | ANY/catch-all | Mostrar onboarding | No | SSID escaneados | Ninguna | GET/catch-all solo en portal; HTML contextual y headers. |
| `/wifisave` | POST | Guardar Wi-Fi y alta admin | Sí | SSID, passwords, token | SSID obligatorio | POST; ventana BOOT, CSRF de provisioning, longitudes y escape. |
| `/update` | Ausente desde P5.1 | Firmware OTA | — | — | Compilado fuera | Debe permanecer ausente. |

En la baseline P5.2, el scheduler que usaba la URL persistida no era una ruta
HTTP y no recibía una protección nueva por autenticar `/fetchnow` o
`/setupdate`. P5.3a elimina ese scheduler, ambas rutas, la URL y su estado de
stats/UI.

### Mapa conservador de la candidate P5.2

| Amenaza | Efecto directo de la candidate | Estado conservador |
| --- | --- | --- |
| TM-01 | Guard central, inventario de métodos, sesión y headers. | Candidata a `MITIGATED`; HTTP claro y exposición de interfaz siguen abiertos. |
| TM-02 | Stats exige Host/sesión y usa JSON contextual/no-store. | Candidata a `MITIGATED`; minimización de IP/MAC/URL aún no cumple el cierre. |
| TM-16 | Escape HTML/JSON, DOM seguro, script propio y CSP. | Candidata a `MITIGATED`; falta corpus en navegador y datos legacy. |
| TM-17 | Mutaciones POST con token CSRF ligado a sesión; token propio de portal. | Candidata a `MITIGATED`; falta matriz HTTP/browser/HIL completa. |
| TM-18 | Verificador local, bootstrap físico, sesión, autorización y throttle. | Candidata a `MITIGATED`; el canal HTTP no protege contraseña/cookie on-path. |
| TM-19 | Allowlist estricta de IPv4 local/`c3adblock.local` y puerto 80. | Candidata a `MITIGATED`; falta browser rebinding/HIL y restricción por interfaz. |
| TM-03 a TM-06, TM-08 | La autorización reduce el atacante anónimo/CSRF. | `OPEN`: semántica, límites, recovery, atomicidad, TLS y SSRF no se corrigen. |
| TM-10, TM-11, TM-30 | BOOT controla alta/reset admin y el estado falla cerrado. | `OPEN`: portal abierto/HTTP, NVS físico y recovery integral siguen pendientes. |
| TM-20 | Throttle solo para login. | `OPEN`: no hay rate limiting general de DNS, panel, upload o fetch. |
| Resto | Sin cambio deliberado en P5.2. | Conserva el estado previo. |

### Delta P5.3a — pipeline manual-only

P5.2 y P5.2a están committed y pushed en `bbeacda`; una persona confirmó ambos
jobs de CI verdes y el HIL completo solicitado. Esa evidencia no acredita la
candidate P5.3a. El inventario actual de blocklist es:

| Superficie | Estado P5.3a | Riesgo residual |
| --- | --- | --- |
| `POST /upload` | Se conserva con Host, sesión y CSRF; escribe solo `/blocklist.new`, valida en streaming y promociona con `/blocklist.old` como rollback. | HTTP claro, sin firma/procedencia, WebServer multipart síncrono y HIL de I/O/cortes pendientes. |
| `/fetchnow` | Ruta y handler ausentes. | La ausencia debe confirmarse en CI/binario y HIL 404/405. |
| `/setupdate` | Ruta, handler, URL e intervalo ausentes. | Un `/update.cfg` legacy queda físicamente inerte y puede retener una URL/token hasta restaurar LittleFS. |
| Scheduler/HTTP/TLS | `HTTPClient`, `NetworkClientSecure`, `setInsecure()`, redirects y scheduler compilados fuera. | Una futura reintroducción necesita hora, CA, pin de destino, autenticidad y otra decisión. |
| Montaje LittleFS | `LittleFS.begin(false)` y recovery antes de cualquier red; sin copia válida se detiene fail-closed. | Durabilidad real de LittleFS y recuperación USB aún necesitan HIL destructivo autorizado. |

El máximo de candidato es 524.285 B, exactamente 104.857 registros little-endian
de cinco bytes, estrictamente ascendentes y sin duplicados. Activo y rollback
legacy pueden seguir validándose hasta 1.250.000 B, pero nunca se borran antes de
que un candidato nuevo quepa, se cierre y se valide.

La matriz de corte tiene seis fronteras: (1) durante upload, activo gana y se
elimina el parcial; (2) tras cerrar candidate, activo gana y elimina staging no
confirmado; (3) tras validar candidate pero antes de `active -> old`, activo gana;
(4) tras `active -> old`, old válido se restaura; (5) tras `new -> active`, el
nuevo activo válido gana; (6) antes de limpiar old, el nuevo activo gana y old se
elimina. Esto está modelado en host, no probado todavía contra power-loss real.

El request multipart completo tiene un gate temprano de 528.381 B: máximo de
archivo más 4.096 B de framing. El límite streamed de 524.285 B se aplica por
chunks independientemente de `Content-Length`. El headroom fijo puede rechazar
de forma conservadora un filename/framing excepcional. Los guards de parte
adicional y transacción huérfana son estáticos/modelados; no demuestran cliente
lento, desconexión, timeout, recuperación del loop/DNS ni rate limiting real.

Validación local P5.3a: 163 tests y Ruff correctos; PlatformIO `SUCCESS`, 50.684
B de RAM, 1.122.703 B enlazados y `firmware.bin` de 1.160.704 B con SHA-256
`D1A24F2D579D6B1617850B07E6FA2A403CBF90E08DDD5DD033475D33B7C34F2C`. Quedan
215.552 B físicos. Los tres warnings corresponden al chequeo remoto de
dependencias omitido sin Internet. `ci_checks repository`, los diff checks y el
gate de archivos protegidos pasan localmente; CI real y HIL P5.3a siguen
pendientes. TM-06, TM-08, TM-12 a TM-15 y
TM-25 son como máximo candidatas a `MITIGATED`; ninguna queda `CLOSED` sin esa
evidencia y sin cumplir su aceptación completa.

No se cambia todavía el agregado formal por añadir documentación o tests
estáticos. Después de validar la revisión exacta, las seis candidatas directas
pueden pasar a `MITIGATED`, nunca a `CLOSED` sin browser/HIL y sin cumplir sus
condiciones completas.

### Delta P5.5 — procedencia firmada del upload manual

P5.5 conserva el formato activo y la ausencia de fetch remoto. Cada nuevo
`POST /upload` requiere un proof de 128 bytes firmado con ECDSA P-256/SHA-256
por la única clave pública autorizada (Key ID `2173599637`, List ID `1`). Host,
sesión y CSRF se comprueban antes del proof; un proof ausente, malformado o no
autorizado falla antes de crear `/blocklist.new`.

El manifest autentica secuencia no nula, tamaño, recuento y SHA-256 del payload.
El firmware comprueba la firma al iniciar el upload, después valida los bytes
persistidos y vuelve a autenticar el active tras los renames. El proof temporal
`/blocklist.new.auth` se conserva hasta confirmar el nuevo active; se retira
mientras old todavía permite rollback y old se elimina al final. En recuperación,
un candidato sin proof nunca gana y el estado active+proof sin candidate se trata
como marcador de promoción interrumpida.

Esto reduce la posibilidad de que una sesión administrativa comprometida instale
una política arbitraria, pero no elimina el riesgo del canal HTTP ni el DoS de
upload. Las listas active/old legacy unsigned continúan siendo boot-compatibles,
V1 permite replay de releases correctamente firmadas y no conserva attestation
del active en reposo. TM-06 y TM-13 siguen como máximo candidatas a `MITIGATED`
hasta CI, multipart real y HIL de cortes; no pasan a `CLOSED`.

Validación local P5.5: 231 tests, Ruff, `ci_checks repository`, diff checks y
archivos protegidos correctos. PlatformIO `SUCCESS`: 50.828 B RAM,
1.127.265 B enlazados, margen enlazado 248.991 B y `firmware.bin` de 1.165.808 B
con 210.448 B físicos libres. Su SHA-256 es
`67DFDE5BE7A11D608B624AA3C8E1DD56896696986B0CD8EB1BF6A0DE699814B7`.
Frente a P5.4 aumenta 144 B RAM, 4.088 B enlazados y 4.448 B físicos. CI real y
HIL siguen pendientes.

### Delta P6.1 — parser acotado y correlación upstream

P6.1 conserva UDP/53, Quad9, el buffer máximo de 600 bytes y una única consulta
upstream síncrona. La lógica pura pasa a `src/dns_protocol.cpp`, que también
compila directamente el harness nativo. Queries y respuestas se validan con
límites explícitos antes de cualquier decisión o forward; preguntas comprimidas,
truncadas, de clase no IN, con opcode no soportado o con QDCOUNT distinto de uno
se rechazan en lugar de interpretarse parcialmente.

Para una query permitida, el firmware conserva el ID del cliente, usa un ID
upstream generado por el dispositivo y solo acepta un datagrama cuyo origen sea
el resolver configurado en puerto 53 y cuyo ID, QR, opcode, QDCOUNT, QNAME,
QTYPE y QCLASS correspondan al contexto guardado. El ID del cliente solo se
restaura después de validar la respuesta completa. Los datagramas stale o falsos
se limpian y el firmware continúa dentro de un timeout de 1.000 ms y un máximo
de ocho candidatos.

La API `NetworkUDP` conserva un `rx_buffer` tras una lectura parcial y bloquea
las recepciones siguientes. P6.1 evita esa condición: un datagrama superior a
600 bytes se descarta completo mediante `clear()`, y una lectura aceptada debe
consumir exactamente el tamaño anunciado. Antes de cada envío se limpia el
buffer previo y se drena la cola con un presupuesto de ocho datagramas; si el
presupuesto se agota, la consulta falla sin enviar o aceptar datos no asociados.

Los tests permanentes ejecutan corpus determinista, bordes y mutaciones sobre el
mismo código C++ de producción. El gate pytest de Windows ejecuta 100.000
mutaciones con ASan y la validación local adicional completó 1.000.000; el job
Linux definido para CI ejecuta 1.000.000 con ASan+UBSan y seed `0x4E534D`.
La mera presencia del job no acredita una ejecución real. También siguen
pendientes el HIL con upstream UDP controlado, la carga/timeout en la placa y la
regresión A/AAAA. TM-22 y TM-23 pasan como máximo a candidatas a `MITIGATED`, no
a `CLOSED`, hasta disponer de CI real confirmada y HIL.

## Registro detallado

### TM-01 — Plano administrativo HTTP expuesto

- **ID:** TM-01.
- **Estado P5.2:** candidata a `MITIGATED`; todas las rutas STA tienen método y
  guard explícitos, pero HTTP claro y los tests browser/HIL dejan riesgo residual.
- **Activo afectado:** configuración, política de bloqueo, disponibilidad y
  privacidad administrativa.
- **Atacante requerido:** cualquier cliente de la LAN; también un atacante WAN
  si existe exposición externa.
- **Superficie:** `WebServer web(80)`, `/` y todas las rutas registradas en
  `src/main.cpp:411-425`.
- **Escenario:** el atacante descubre `c3adblock.local` o la IP, abre HTTP y
  enumera o invoca el plano administrativo completo.
- **Impacto:** lectura de estado, cambio de política, borrado de Wi-Fi,
  sustitución de artefactos y cadenas hacia ejecución de firmware.
- **Probabilidad:** Alta en una LAN con clientes no confiables.
- **Severidad:** HIGH; las rutas de ejecución de firmware se clasifican aparte
  como CRITICAL.
- **Controles actuales:** P5.2 añade verificador local, sesión RAM, guards
  separados de lectura/mutación, métodos explícitos, CSRF, allowlist de `Host` y
  headers defensivos. El panel solo se registra tras conectar en modo STA.
- **Controles ausentes:** confidencialidad/autenticidad del canal HTTP,
  restricción explícita por interfaz/subred, rate limiting general y HIL de la
  matriz completa.
- **Corrección propuesta:** conservar el inventario fail-closed, validar toda ruta
  nueva y resolver el canal/interfaz antes de PILOT; compilar el panel fuera si
  no puede protegerse adecuadamente.
- **Test necesario:** matriz automatizada de ruta por método, estado de sesión,
  perfil y origen; una ruta nueva debe fallar cerrada si no está inventariada.
- **Condición de aceptación:** ninguna ruta administrativa devuelve datos ni
  cambia estado sin la autorización prevista; las capacidades deshabilitadas
  responden 404/405 y no aparecen en el binario ni en la UI.

### TM-02 — Exposición de `/stats.json`

- **ID:** TM-02.
- **Estado P5.2:** candidata a `MITIGATED`; Host y sesión bloquean acceso anónimo,
  pero la respuesta autenticada aún contiene datos que deben minimizarse.
- **Activo afectado:** IP y MAC de clientes, patrón de actividad, URL de update,
  heap, RSSI, temperatura y configuración operativa.
- **Atacante requerido:** cliente LAN o sitio que complete DNS rebinding.
- **Superficie:** `handleStats()` en `src/main.cpp:194-208` y polling cada tres
  segundos en `src/page.h:39-65`.
- **Escenario:** una petición no autenticada obtiene el inventario de hasta 96
  clientes, contadores, bans, dominios personalizados y una URL que podría
  contener parámetros sensibles.
- **Impacto:** reconocimiento de la red, correlación de actividad y fuga de
  configuración útil para ataques posteriores.
- **Probabilidad:** Alta.
- **Severidad:** MEDIUM; escala a HIGH junto con TM-19 o secretos en URL.
- **Controles actuales:** exige Host permitido y sesión, usa
  `application/json`, escape JSON de caracteres de control y
  `Cache-Control: no-store`; no se guarda historial de dominios.
- **Controles ausentes:** minimización/redacción de URL, IP, MAC y clientes,
  paginación/límite de respuesta y test browser de rebinding.
- **Corrección propuesta:** proteger la ruta, devolver solo datos necesarios,
  excluir URLs completas y usar serialización JSON contextual y acotada.
- **Test necesario:** tests de esquema, autorización, redacción, caracteres de
  control, cache headers, lista máxima y rebinding.
- **Condición de aceptación:** una petición no autorizada obtiene 401/403 o 404,
  sin cuerpo de datos. `/stats.json` autorizado queda limitado a los campos
  agregados `blocked`, `allowed`, `domains`, `rssi`, `heap` y `uptime`, a 2.048
  bytes y a JSON válido; IP, MAC, URL, custom domains y clientes requieren otra
  ruta autenticada y paginada o se eliminan.

### TM-03 — Manipulación y DoS mediante `/ban`

- **ID:** TM-03.
- **Estado P5.2:** `OPEN`; POST+sesión+CSRF reduce acceso no autorizado, no
  corrige la semántica toggle ni la persistencia de bans.
- **Activo afectado:** disponibilidad DNS por cliente y persistencia de bans.
- **Atacante requerido:** cliente LAN o navegador víctima de CSRF.
- **Superficie:** `handleBan()` en `src/main.cpp:209-212` y GET generado en
  `src/page.h:47`.
- **Escenario:** el atacante alterna repetidamente el ban de una IP o llena la
  tabla de clientes con IP arbitrarias. Además, `saveBanned()` reconstruye desde
  `clients[]` y pierde bans cargados cuyo cliente aún no apareció; con 96 clientes
  llenos, una IP persistida pero no materializada puede eludir el ban.
- **Impacto:** denegación selectiva de DNS, estado persistente inesperado y
  agotamiento de la tabla.
- **Probabilidad:** Alta.
- **Severidad:** HIGH.
- **Controles actuales:** P5.2 exige POST, sesión y CSRF; además existen
  `IPAddress.fromString()`, máximo de 96 clientes y 32 bans persistidos. Esos
  topes no preservan correctamente bans no materializados.
- **Controles ausentes:** operación idempotente, validación de pertenencia a la
  LAN, expiración, persistencia recuperable y respuesta de error fiable.
- **Corrección propuesta:** POST autenticado con estado explícito `ban=true` o
  `false`, token CSRF, objetivo conocido, cuota y expiración administrable.
- **Test necesario:** IP inválida/ajena, replay, ban cargado antes de ver al
  cliente, modificación de otro ban, tabla llena, reboot, escritura fallida y
  dos clientes concurrentes.
- **Condición de aceptación:** solo un administrador autorizado modifica un
  cliente válido; replay no invierte el resultado, modificar uno conserva todos
  los demás bans y una IP banned sigue aplicándose aun con la tabla llena. Todo
  fallo se reporta sin alterar el archivo anterior.

### TM-04 — Manipulación mediante `/addblock` y `/unblock`

- **ID:** TM-04.
- **Estado P5.2:** `OPEN`; access control y output encoding reducen explotación,
  pero validación DNS y persistencia segura quedan pendientes.
- **Activo afectado:** integridad de la política DNS y disponibilidad de dominios
  legítimos.
- **Atacante requerido:** cliente LAN o navegador víctima de CSRF.
- **Superficie:** `addCustom()`/`removeCustom()` en `src/main.cpp:100-111`, rutas
  en `src/main.cpp:414-415` y UI en `src/page.h:48,52`.
- **Escenario:** se añaden cadenas arbitrarias que contengan un punto, o se
  eliminan bloqueos legítimos, persistiendo el cambio en LittleFS.
- **Impacto:** sobrebloqueo, evasión de bloqueo y entrada para XSS almacenado.
- **Probabilidad:** Alta.
- **Severidad:** HIGH.
- **Controles actuales:** P5.2 exige POST, sesión y CSRF y renderiza el valor como
  texto; también aplica trim, minúsculas, eliminación de `www.`, deduplicación y
  máximo de 200 entradas.
- **Controles ausentes:** validación DNS LDH/longitudes, límite de request,
  escritura atómica y estados HTTP precisos.
- **Corrección propuesta:** validador canónico equivalente a la política del
  generador P2, POST autenticado, tamaño acotado y persistencia segura.
- **Test necesario:** labels de 63/64, total de 253/254, IP, Unicode, wildcard,
  payloads HTML/JS, duplicados, límite 200 y fallo de escritura.
- **Condición de aceptación:** solo dominios conformes a la política documentada
  se almacenan; una entrada rechazada o un error de persistencia no cambia la
  política y produce un código de error inequívoco.

### TM-05 — Borrado Wi-Fi mediante `/forgetwifi`

- **ID:** TM-05.
- **Estado P5.2:** `OPEN`; ya no es anónimo/GET, pero borrar Wi-Fi aún requiere
  una política de presencia física y recovery más fuerte.
- **Activo afectado:** credenciales Wi-Fi y disponibilidad del servicio DNS.
- **Atacante requerido:** cliente LAN o sitio malicioso que induce una petición.
- **Superficie:** handler HTTP_ANY de `src/main.cpp:416-417`.
- **Escenario:** una petición GET borra NVS, reinicia el equipo y puede hacerlo
  entrar en el portal cautivo abierto.
- **Impacto:** DoS persistente, pérdida de conectividad y ventana para secuestro
  del onboarding.
- **Probabilidad:** Alta.
- **Severidad:** HIGH.
- **Controles actuales:** P5.2 exige POST, sesión y CSRF; solo se borra el
  namespace `wifi` y existe recuperación física mediante BOOT.
- **Controles ausentes:** reautenticación/presencia física en la operación,
  comprobación de `prefs.clear()` y rollback.
- **Corrección propuesta:** retirar la ruta del perfil PILOT o exigir sesión
  reciente más gesto físico local; no abrir portal por una petición remota.
- **Test necesario:** petición anónima/CSRF, error NVS, reinicio, fallback
  `secrets.h`, presencia física y reintento.
- **Condición de aceptación:** ninguna petición de red aislada puede borrar Wi-Fi
  ni activar onboarding; el borrado autorizado se verifica tras reinicio y deja
  un camino de recuperación documentado.

### TM-06 — Sustitución destructiva mediante `/upload`

- **ID:** TM-06.
- **Estado P5.5:** candidata a `MITIGATED`, no `CLOSED`; el algoritmo destructivo
  descrito debajo es histórico y faltan CI/multipart/power-loss HIL.
- **Activo afectado:** blocklist, LittleFS, disponibilidad y política DNS.
- **Atacante requerido:** cliente LAN o navegador capaz de enviar un formulario
  cross-origin.
- **Superficie histórica:** `/upload`, `handleUpload()` y el swap destructivo de
  la baseline P5.2.
- **Escenario histórico:** al comenzar el upload se cerraba y borraba la lista válida; un
  aborto, short write, filesystem lleno o blob malicioso deja filtrado fail-open
  o instala cualquier múltiplo de cinco bytes. POST vacío/raw/urlencoded o
  multipart sin fichero puede ejecutar el callback sin objeto upload y provocar
  dereferencia inválida/reset, pendiente de confirmar con harness/HIL.
- **Impacto:** pérdida de protección, desgaste/llenado de flash y corrupción de
  política persistente.
- **Probabilidad:** Alta.
- **Severidad:** HIGH.
- **Controles actuales P5.5:** sesión/CSRF se revalidan antes de escribir y antes
  de promocionar; límite streamed, writes comprobados, validador acotado,
  active/new/old, rollback y boot recovery conservan last-known-good. Un
  dispatcher alineado con el parser del core solo accede a `web.upload()` para
  multipart y rechaza raw/urlencoded con 415 sin persistir bytes. P5.5 exige un
  proof firmado antes de abrir staging, vincula manifest y payload persistido y
  solo recupera un candidato acompañado por autenticación válida.
- **Controles ausentes:** anti-replay, attestation de listas active/legacy,
  prueba HTTP multipart real, timeout y rate limit; short write, filesystem
  lleno, fallos de rename y cortes solo se modelan/inspeccionan hasta completar
  HIL.
- **Corrección propuesta:** mantener el upload fuera de PILOT hasta completar el
  HIL multipart/LittleFS, la autenticidad del artefacto y los límites de tasa; no
  volver al swap destructivo ni ampliar el máximo para forzar que una lista quepa.
- **Test necesario:** abortar en cada chunk, short write, out-of-space, archivo
  enorme/desordenado/duplicado y fallo de rename; añadir POST vacío, raw,
  urlencoded, multipart sin fichero y Content-Type incorrecto, con reboot tras
  cada punto.
- **Condición de aceptación:** ante cualquier fallo sigue activa exactamente la
  lista anterior. `MAX_BLOCKLIST_UPDATE_BYTES` debe estar codificado y no superar
  el espacio de staging medido conservando live+reserva LittleFS; tamaños mayores
  se rechazan antes de abrir el temporal. La lista debe ser múltiplo de cinco,
  lectura completa, orden estrictamente ascendente, sin hashes duplicados y con
  integridad/autenticidad exigida por su origen; ningún I/O fallido devuelve éxito.

### TM-07 — Firmware arbitrario mediante `/update`

- **ID:** TM-07.
- **Estado P5.1:** `MITIGATED`; el camino desapareció de fuente y binario, pero
  falta comprobar 404/405 explícitamente y completar el recovery destructivo en
  HIL autorizado.
- **Activo afectado:** firmware, credenciales, tráfico DNS y control total del
  dispositivo.
- **Atacante requerido:** cualquier cliente LAN; una exposición WAN agrava el
  alcance.
- **Superficie:** en la baseline P4, `/update`, `handleFwUpload()`, `Update` y el
  formulario de `src/page.h`; todos están ausentes desde P5.1.
- **Escenario:** el atacante sube un `firmware.bin` elegido por él sin presentar
  credencial, firma ni versión autorizada. Un multipart sin fichero puede llegar
  al handler final con `Update.hasError()==false` y reiniciar; otros POST
  malformados pueden tocar `web.upload()` sin upload válido.
- **Impacto:** ejecución persistente de código, exfiltración de Wi-Fi, DNS
  malicioso y eliminación de controles.
- **Probabilidad:** Alta en una LAN no totalmente confiable.
- **Severidad:** CRITICAL.
- **Controles actuales:** P5.1 compila fuera ruta, handler, librería y UI; CI y
  escaneo de artefactos lo comprueban. La actualización autorizada queda por USB.
- **Controles ausentes:** firma/provenance del artefacto USB, secure boot, versión,
  anti-rollback y confirmación de boot si algún día vuelve un canal remoto.
- **Corrección propuesta:** mantener la ausencia. Solo se reabrirá tras un diseño
  separado de firmware firmado, anti-downgrade y recovery.
- **Test necesario:** análisis de símbolos/rutas/UI, petición 404/405 en HIL,
  POST vacío/raw/urlencoded/multipart sin fichero antes de retirarla, escaneo de
  puertos autorizado, build size y prueba posterior de recuperación USB con
  aprobación humana.
- **Condición de aceptación:** el binario DEVELOPMENT y PILOT no contienen ni
  registran `/update`; no existe camino de firmware por HTTP y el build conserva
  una recuperación física documentada.

### TM-08 — Fetch y configuración inseguros

- **ID:** TM-08.
- **Estado P5.3a:** candidata a `MITIGATED`, no `CLOSED`; `/fetchnow`,
  `/setupdate`, configuración y scheduler están ausentes de fuente, pendiente de
  confirmación CI/binario/HIL.
- **Activo afectado:** blocklist, configuración persistente, disponibilidad DNS
  y heap.
- **Atacante requerido:** cliente LAN, CSRF o servidor remoto controlado.
- **Superficie histórica:** `/fetchnow`, `/setupdate`, `load/saveUpdateCfg()` y
  scheduler de la baseline P5.2.
- **Escenario histórico:** se persistía una URL arbitraria y se disparaba una descarga
  síncrona, grande, lenta, parcial o repetida; un intervalo extremo puede
  desbordar la aritmética de milisegundos.
- **Impacto:** DoS, fail-open de filtrado, llenado de LittleFS y persistencia de
  un origen atacante.
- **Probabilidad:** Alta.
- **Severidad:** HIGH.
- **Controles actuales P5.3a:** no hay ruta, URL, intervalo, scheduler ni cliente
  remoto. `/update.cfg` no se interpreta y el upload manual es transaccional.
- **Controles ausentes:** confirmar ausencia en CI/binario y HIL; el archivo
  legacy puede permanecer físicamente y retener una URL/token hasta recuperar
  LittleFS. No existe una arquitectura segura para reactivar fetch.
- **Corrección propuesta:** mantener fetch remoto deshabilitado hasta completar
  TM-13, TM-14 y TM-15; usar estado acotado, fallo cerrado y configuración
  persistida atómicamente.
- **Test necesario:** URL/intervalo límite, `uint32_t` wrap, chunked sin fin,
  timeout, content-length falso, write corto, reinicio y concurrencia DNS.
- **Condición de aceptación:** el fetch es una máquina de estados y cada paso
  devuelve control al loop en 5 ms como máximo bajo el cliente HTTP simulado;
  aplica timeout total de 20 s, idle de 15 s y el máximo de TM-13. Timeout,
  exceso o I/O fallido conservan lista y configuración anteriores y dan error.

### TM-09 — ArduinoOTA sin autenticación

- **ID:** TM-09.
- **Estado P5.1:** `MITIGATED`; código, dependencia, símbolos y strings están
  ausentes y el HIL funcional no los reintrodujo, pero falta un escaneo explícito
  de anuncio/puerto en la placa.
- **Activo afectado:** firmware y control completo del dispositivo.
- **Atacante requerido:** cliente con alcance IP a la STA.
- **Superficie:** en la baseline P4, `ArduinoOTA.begin()` y
  `ArduinoOTA.handle()`; ambos están ausentes desde P5.1.
- **Escenario:** el hostname conocido `c3adblock` anuncia/acepta una actualización
  ArduinoOTA sin contraseña ni firma de firmware.
- **Impacto:** el mismo compromiso persistente y total de TM-07 por un protocolo
  distinto que no pasa por el panel.
- **Probabilidad:** Alta.
- **Severidad:** CRITICAL.
- **Controles actuales:** P5.1 eliminó API, setup, loop, dependencia y backend
  Update; análisis de fuente/ELF/map/binario y CI protegen la ausencia.
- **Controles ausentes:** escaneo HIL específico y autenticidad/provenance del
  único camino físico restante.
- **Corrección propuesta:** mantener `ArduinoOTA` ausente y conservar únicamente
  actualización física autorizada.
- **Test necesario:** símbolos y strings ausentes en ELF/map, servicio OTA no
  anunciado ni escuchando en HIL y regresión de DNS/panel.
- **Condición de aceptación:** no se enlaza `ArduinoOTA`, no se llama a su loop y
  ningún servicio de actualización de firmware está disponible por red.

### TM-10 — Portal cautivo abierto o activado por fallo

- **ID:** TM-10.
- **Estado P5.2a:** `OPEN`; el alta/reset administrativo y `/wifisave` exigen un
  hold BOOT runtime de tres segundos y token de provisioning, pero el AP y el
  transporte continúan abiertos.
- **Activo afectado:** credenciales Wi-Fi, asociación de red y control del
  onboarding.
- **Atacante requerido:** equipo dentro del alcance radio durante onboarding o
  un fallo de conexión al arrancar.
- **Superficie:** `connectWiFi()` y `startConfigPortal()` en
  `src/main.cpp:328-389`.
- **Escenario:** tras 20 s sin conexión, el ESP abre indefinidamente un AP sin
  contraseña y nombre predecible. Antes del gesto físico solo ofrece estado
  read-only; después del hold, cualquier equipo cercano puede competir por el
  formulario y enviar SSID/password por HTTP mientras la autorización siga viva.
- **Impacto:** secuestro de configuración, exposición de credenciales al medio,
  DoS y conexión del dispositivo a una red atacante.
- **Probabilidad:** Alta durante onboarding; Media en operación normal.
- **Severidad:** HIGH.
- **Controles actuales:** portal y panel normal no se registran simultáneamente;
  `/wifisave` usa POST, exige SSID, CSRF aleatorio y autorización física runtime;
  release/rebote reinician el contador BOOT.
- **Controles ausentes:** AP protegido o secreto efímero, expiración de la
  autorización, timeout del portal, límite de intentos, cifrado de transporte,
  validación y confirmación de asociación antes de persistir.
- **Corrección propuesta:** portal solo en primer arranque o ventana iniciada por
  BOOT mantenido al menos tres segundos, con timeout de cinco minutos y segunda
  confirmación física antes de persistir; validar longitudes y cerrar al fallar.
- **Test necesario:** fallo DHCP/SSID, atacante concurrente, timeout, reboot,
  credenciales inválidas, portal no solicitado y captura que confirme ausencia
  de secretos en logs.
- **Condición de aceptación:** una pérdida ordinaria de Wi-Fi nunca abre el AP.
  La ventana solo abre tras el gesto de tres segundos, expira a los cinco minutos
  y cada envío exige otra confirmación BOOT dentro de 30 s; las credenciales solo
  se confirman tras 30 s de asociación estable, o se descartan.

### TM-11 — Credenciales y estado en NVS

- **ID:** TM-11.
- **Estado P5.2:** `OPEN`; el password admin se almacena solo como verificador
  salted, mientras credenciales Wi-Fi y seguridad física de NVS no cambian.
- **Activo afectado:** SSID, contraseña Wi-Fi y capacidad de borrar/restaurar la
  configuración.
- **Atacante requerido:** acceso físico a flash, firmware ya comprometido o fallo
  de NVS.
- **Superficie:** `Preferences` en `src/main.cpp:332-370,400-417`.
- **Escenario:** las credenciales se almacenan como strings en el namespace
  `wifi`; una extracción física o firmware malicioso puede leerlas, y fallos de
  `putString()`/`clear()` no se comprueban.
- **Impacto:** acceso a la Wi-Fi del usuario, falsa sensación de borrado y
  onboarding inconsistente.
- **Probabilidad:** Media global; la extracción física es Baja, pero los errores
  de estado durante guardar/borrar son Media.
- **Severidad:** MEDIUM, asumiendo que acceso físico sostenido no está totalmente
  dentro del control de software del MVP.
- **Controles actuales:** namespace dedicado, contraseña no impresa por el código
  normal, secretos de build fuera de Git y borrado mediante BOOT o ruta web.
- **Controles ausentes:** comprobación de retornos, límites, esquema/versionado,
  detección de estado parcial y cifrado NVS/flash documentado.
- **Corrección propuesta:** validar y comprobar cada operación; minimizar datos;
  documentar el riesgo físico. Cifrado NVS/flash y eFuses requieren un diseño y
  aprobación humana separados por su irreversibilidad y recuperación.
- **Test necesario:** adapter falso de Preferences para ausencia, dato parcial,
  namespace lleno, corrupción, short write y clear fallido; HIL de borrado.
- **Condición de aceptación:** un error no se anuncia como guardado/borrado. Tras
  reboot, solo `ssid` y `pass` completos forman estado `CONFIGURED`; ausencia de
  ambos es `UNCONFIGURED`; cualquier combinación parcial es `CONFIG_ERROR`, no
  inicia DNS/panel y requiere recovery físico. Un clear válido deja ambas claves
  ausentes y ningún estado imprime o expone la contraseña.

### TM-12 — Autoformato con `LittleFS.begin(true)`

- **ID:** TM-12.
- **Estado P5.3a:** candidata a `MITIGATED`, no `CLOSED`; el autoformato se
  retiró y falta validar corrupción/recovery físico en HIL.
- **Activo afectado:** blocklist, bans, dominios personalizados y configuración
  de update.
- **Atacante requerido:** no es necesario; basta corrupción, incompatibilidad o
  fallo de montaje. Un atacante que provoque escrituras aumenta la probabilidad.
- **Superficie histórica:** `LittleFS.begin(true)` en la baseline P5.2.
- **Escenario histórico:** al fallar el montaje, `true` permitía formatear automáticamente y
  borrar toda la política; el firmware después continúa arrancando.
- **Impacto:** pérdida silenciosa de configuración y filtrado fail-open.
- **Probabilidad:** Media durante cortes, desgaste o imágenes incompatibles.
- **Severidad:** HIGH.
- **Controles actuales P5.3a:** `LittleFS.begin(false)`; mount o recovery fallidos
  detienen el firmware antes de Wi-Fi/DNS/panel y exigen recuperación USB.
- **Controles ausentes:** HIL con filesystem corrupto/cortes, preservación de una
  imagen de diagnóstico y autenticidad/procedencia de la imagen LittleFS de
  recuperación.
- **Corrección propuesta:** montar con `false`; ante fallo no formatear, no
  presentar estado sano y ofrecer recuperación explícita que preserve una copia
  para diagnóstico.
- **Test necesario:** mock de mount fallido y HIL con filesystem corrupto; probar
  que ningún byte se borra antes de aprobación de recuperación.
- **Condición de aceptación:** un fallo de montaje nunca llama a format, no abre
  UDP/53 ni el panel normal y entra en `FS_RECOVERY_REQUIRED`; solo una acción
  física separada puede autorizar recuperación, conservando antes una imagen de
  diagnóstico cuando sea legible.

### TM-13 — Blocklist no transaccional ni validada

- **ID:** TM-13.
- **Estado P5.5:** candidata a `MITIGATED`, no `CLOSED`; el swap destructivo
  descrito debajo es histórico y la transacción autenticada/recovery necesita HIL
  de fallos y cortes reales.
- **Activo afectado:** integridad, autenticidad y disponibilidad de la blocklist.
- **Atacante requerido:** cliente LAN, servidor remoto o fallo de I/O/potencia.
- **Superficie histórica:** `beginBlocklistSwap()`, `commitNewBlocklist()` y el
  fetch de la baseline P5.2; esos helpers están ausentes en P5.3a.
- **Escenario histórico:** la lista viva se eliminaba antes de recibir la nueva; solo se
  valida tamaño positivo múltiplo de cinco, se ignora el resultado de rename y
  `numHashes=0` fuerza fail-open. En boot se usa `size()/5` sin validar resto,
  orden o unicidad; `seek/read` no se comprueban. La condición `numHashes` también
  desactiva los custom domains cuando falta la lista principal.
- **Impacto:** política arbitraria, lista desordenada que produce falsos
  negativos, corrupción y pérdida de bloqueo tras cualquier fallo.
- **Probabilidad:** Alta porque ocurre en cada update y hay rutas no autenticadas.
- **Severidad:** HIGH.
- **Controles actuales P5.5:** validador streaming acotado, límite 524.285 B,
  orden estricto/unicidad, writes completos, active/new/old, rollback comprobado,
  reapertura/revalidación y recovery determinista antes de red. El proof ECDSA
  autentica metadata y SHA-256 en ingreso y se mantiene hasta confirmar el active.
- **Controles ausentes:** anti-replay y attestation permanente de active/legacy,
  journaling/durabilidad garantizada, fault injection C++ real, multipart en
  WebServer y power-cut HIL.
- **Corrección propuesta:** validar en streaming a un staging que quepa, cerrar y
  verificar antes de commit, conservar la lista activa y recuperar anterior o
  nueva tras reinicio. Si no caben dos copias, rechazar sin tocar la viva o
  mantener updater deshabilitado.
- **Test necesario:** fixtures válidas/desordenadas/duplicadas/truncadas, fault
  injection en boot y open/seek/read/write/flush/close/rename, custom sin lista
  principal y power-cut HIL en cada transición.
- **Condición de aceptación:** después de cualquier fallo o reboot queda activa
  exactamente la versión anterior o la nueva. La nueva debe respetar el
  `MAX_BLOCKLIST_UPDATE_BYTES` que quepa con live+reserva, múltiplo de cinco,
  lectura completa, orden estricto, unicidad e integridad/autenticidad según
  origen; nunca queda una parcial ni `numHashes=0` por efecto del update.

Restricción física histórica: LittleFS tiene 1.376.256 bytes y P2 permitía blobs
de hasta 1.250.000 bytes, por lo que no cabían live y staging al máximo. P5.3a
reduce solo los candidatos nuevos a 524.285 B; un activo legacy puede leerse
hasta el máximo anterior y el upload falla sin borrarlo si no existe espacio para
coexistir. El slot OTA de app no se usa como staging.

### TM-14 — HTTP y TLS con `setInsecure()`

- **ID:** TM-14.
- **Estado P5.3a:** candidata a `MITIGATED`, no `CLOSED`; la superficie remota
  está compilada fuera, pendiente de CI/binario/HIL para la revisión exacta.
- **Activo afectado:** autenticidad de blocklist y confidencialidad/integridad de
  la sesión remota.
- **Atacante requerido:** servidor malicioso, DNS comprometido, AP/router hostil
  o intermediario de red.
- **Superficie histórica:** `fetchBlocklist()` de la baseline P5.2.
- **Escenario histórico:** se permitía `http://`; para HTTPS se llamaba a `setInsecure()` y se
  siguen redirects, por lo que no se autentica el servidor ni el destino final.
- **Impacto:** instalación de política maliciosa, fail-open, tracking y DoS.
- **Probabilidad:** Media; aumenta en redes públicas o servidor comprometido.
- **Severidad:** HIGH.
- **Controles actuales P5.3a:** no existe cliente remoto, HTTP, TLS, redirect ni
  `setInsecure()` de blocklist. Solo permanece upload manual local.
- **Controles ausentes:** autenticidad/firma del archivo manual y confirmación de
  ausencia en CI/binario/HIL. Hora, CA, hostname y redirects siguen sin diseño y
  bloquean cualquier reintroducción futura.
- **Corrección propuesta:** descarga remota deshabilitada por defecto. Si vuelve,
  solo HTTPS verificado con confianza mínima mantenible, redirects revalidados y
  firma/digest autenticado; nunca fallback a `setInsecure()`.
- **Test necesario:** certificado inválido/expirado/wrong-host, HTTP, downgrade de
  redirect, CA rotada, reloj incorrecto y contenido alterado, todo sin Internet.
- **Condición de aceptación:** un fallo TLS aborta antes de descargar. Un fallo de
  autenticidad del artefacto puede haber escrito staging, pero ocurre antes de
  tocar/activar live, elimina ese staging y conserva la lista anterior;
  `setInsecure` y HTTP no están presentes en PILOT.

La sección de entrada del bundle CA completo, actualmente descartada por el
linker, mide 68.987 bytes. Incorporarla íntegra consumiría aproximadamente esa
cantidad y dejaría en torno a 8.613 bytes del margen actual antes de código
adicional; el delta enlazado real solo lo decide un build comparativo. Una raíz
mínima reduce flash pero ata el producto a host, rotación y tiempo concretos.

### TM-15 — URLs configurables y SSRF

- **ID:** TM-15.
- **Estado P5.3a:** candidata a `MITIGATED`, no `CLOSED`; URL, rutas, scheduler y
  cliente remoto están ausentes, pendiente de CI/binario/HIL.
- **Activo afectado:** servicios de la LAN, router, dispositivo y secretos
  incluidos accidentalmente en URLs.
- **Atacante requerido:** cliente LAN/CSRF o administrador engañado.
- **Superficie histórica:** argumento `u` de `/setupdate`, redirects y
  `HTTPClient` de la baseline P5.2.
- **Escenario histórico:** el ESP realizaba peticiones a loopback, link-local, IP privadas,
  router, puertos no previstos o un redirect fuera de política; la URL completa
  se guarda, imprime y devuelve en stats.
- **Impacto:** escaneo/acceso desde una posición de red privilegiada, acciones en
  servicios internos, fuga de tokens y bloqueo del loop.
- **Probabilidad:** Alta por falta total de validación y autenticación.
- **Severidad:** HIGH.
- **Controles actuales P5.3a:** no se acepta, persiste, muestra ni solicita una
  URL remota; `/update.cfg` queda inerte y no se interpreta.
- **Controles ausentes:** una copia física legacy puede retener datos sensibles;
  no hay parser/allowlist/pinning porque fetch permanece deshabilitado. Cualquier
  reintroducción debe diseñar todos esos controles antes de abrir un socket.
- **Corrección propuesta:** eliminar URL arbitraria; usar una allowlist compilada
  de URLs exactas `https://host:443/ruta` o dejarla vacía. Rechazar IP literal,
  rangos especiales, credenciales y
  redirects fuera de política; revalidar después de cada resolución.
- **Test necesario:** IPv4/IPv6 local, formatos alternativos, DNS que cambia de
  pública a privada, redirect cross-host/downgrade/loop, userinfo y URL enorme.
- **Condición de aceptación:** con allowlist vacía, cada intento se rechaza antes
  de abrir un socket. Con entradas, solo esquema `https`, host, puerto 443 y ruta
  exactos son alcanzables; toda resolución/redirect se revalida y logs/stats
  nunca contienen query, token o credenciales de URL.

### TM-16 — XSS e inyección JSON/HTML

- **ID:** TM-16.
- **Estado P5.2:** candidata a `MITIGATED`; se eliminaron sinks ejecutables
  conocidos, pendiente de corpus browser y migración de datos legacy.
- **Activo afectado:** sesión futura del administrador, integridad del panel,
  credenciales de onboarding y todas las acciones accesibles al origen del ESP.
- **Atacante requerido:** cliente LAN que persista un dominio, o AP cercano con
  SSID malicioso, más una persona que abra el panel/portal.
- **Superficie:** `jesc()` en `src/main.cpp:190`, custom domains en
  `src/page.h:41-48`, `portalOpts` y SSID reflejado en
  `src/main.cpp:348-369,376`.
- **Escenario:** una cadena con punto se almacena como dominio y se inserta con
  `innerHTML` y un `onclick` inline; un SSID con comillas/markup entra en atributo
  HTML o se refleja sin escape. `jesc()` no cubre controles JSON ni contextos
  HTML/JS.
- **Impacto:** JavaScript bajo el origen del dispositivo, acciones
  administrativas, robo de una futura sesión y portal falso.
- **Probabilidad:** Alta.
- **Severidad:** HIGH.
- **Controles actuales:** P5.2 separa el script, construye contenido dinámico con
  `textContent`/nodos/listeners, aporta escape HTML para los cinco caracteres
  críticos, escape JSON de controles y una CSP sin script inline.
- **Controles ausentes:** validación DNS/URL completa, corpus real de navegador,
  migración de valores legacy y eliminación de `unsafe-inline` para estilos.
- **Corrección propuesta:** mantener encoding por contexto, añadir validadores
  semánticos y ejecutar corpus browser sobre cada fuente persistida/reflejada.
- **Test necesario:** tabla de payloads para JSON, texto, atributo con comilla
  simple/doble y JS; datos legacy persistidos; navegador automatizado sin red.
- **Condición de aceptación:** todos los payloads se rechazan o aparecen como
  texto literal, JSON siempre parsea y no se ejecuta ningún handler inyectado.

### TM-17 — CSRF en operaciones de estado

- **ID:** TM-17.
- **Estado P5.2:** candidata a `MITIGATED`; las mutaciones usan POST y CSRF
  ligado a sesión, pendiente de matriz real de métodos/orígenes.
- **Activo afectado:** toda configuración mutable, Wi-Fi, blocklist y firmware.
- **Atacante requerido:** sitio web malicioso visitado desde un navegador con
  acceso a la LAN; no necesita leer respuestas.
- **Superficie histórica:** GET mutantes `/ban`, `/addblock`, `/unblock`,
  `/forgetwifi`, `/fetchnow`, `/setupdate`, y POST `/upload`, `/update`,
  `/wifisave`. En P5.3a `/fetchnow`, `/setupdate` y `/update` están ausentes; las
  mutaciones restantes son POST con los guards P5.2.
- **Escenario histórico:** imágenes, formularios o peticiones cross-origin activaban cambios;
  una futura cookie agravaría el problema. `web.on(uri, handler)` registra
  HTTP_ANY: `/`, stats y mutaciones sin método aceptan todos los métodos del core.
  CSRF ordinario dispara GET y POST malformado/DoS; cargar un binario elegido
  requiere cliente LAN directo, XSS/rebinding u otra capacidad para construirlo.
- **Impacto:** DoS/reboot, cambio de política y SSRF; la carga binaria arbitraria
  necesita la condición adicional anterior.
- **Probabilidad:** Alta.
- **Severidad:** HIGH.
- **Controles actuales:** toda mutación STA exige POST, sesión y token CSRF; la
  cookie usa `SameSite=Strict`, Host se valida y `/wifisave` usa un token propio
  dentro de la ventana física. No se declara CORS permisivo.
- **Controles ausentes:** validación explícita de Origin/content type donde sea
  útil, reautenticación/presencia física para operaciones destructivas y test de
  todos los métodos alternativos en WebServer real.
- **Corrección propuesta:** mantener GET sin efectos, comprobar método/sesión/
  token antes del handler y añadir controles reforzados a borrados y swaps.
- **Test necesario:** `<img>`, form simple, fetch no-cors, Origin ausente/ajeno,
  token repetido/expirado, POST malformados y todos los métodos alternativos por
  cada ruta HTTP_ANY.
- **Condición de aceptación:** ninguna navegación o request cross-site cambia
  estado; método, sesión, origen y token incorrectos fallan antes del handler.

### TM-18 — Ausencia de autenticación y autorización

- **ID:** TM-18.
- **Estado P5.2:** candidata a `MITIGATED`; existe identidad local y autorización
  central, pero HTTP claro impide considerarla cerrada o apta para PILOT.
- **Activo afectado:** control administrativo total y credenciales futuras.
- **Atacante requerido:** acceso a la LAN, AP cautivo o ruta WAN accidental.
- **Superficie:** todas las rutas HTTP administrativas. ArduinoOTA y `/update`
  de firmware están ausentes desde P5.1.
- **Escenario:** cualquier cliente recibe los mismos privilegios que el dueño;
  no existen roles ni separación entre diagnóstico y operaciones destructivas.
- **Impacto:** toma completa de administración, incluida ejecución persistente de
  firmware mediante TM-07/TM-09.
- **Probabilidad:** Alta.
- **Severidad:** CRITICAL.
- **Controles actuales:** P5.2 usa verificador PBKDF2 con salt en NVS, alta/reset
  bajo BOOT, comparación constant-time, una sesión RAM de 30 minutos, guards por
  ruta y throttle de login sin lockout persistente.
- **Controles ausentes:** canal confidencial/autenticado, prueba de recuperación
  física, posible reautenticación de acciones críticas y rate limiting ajeno al
  login.
- **Corrección propuesta:** validar el diseño en browser/HIL y proteger o retirar
  el canal administrativo antes de PILOT; nunca presentar HTTP+password como
  confidencial.
- **Test necesario:** matriz anónimo/credencial errónea/correcta/expirada por
  ruta, reboot, lockout, recuperación, logs y datos legacy; comprobar que HTTP
  no se presenta como confidencial.
- **Condición de aceptación:** cada acción tiene política explícita y fail-closed;
  no existe credencial por defecto o hardcoded, no se registra y la recuperación
  requiere presencia física.

### TM-19 — DNS rebinding y falta de validación de `Host`

- **ID:** TM-19.
- **Estado P5.2:** candidata a `MITIGATED`; la allowlist rechaza hosts arbitrarios,
  pero falta un ensayo real de rebinding y restricción por interfaz.
- **Activo afectado:** confidencialidad del panel y autoridad administrativa.
- **Atacante requerido:** sitio/control de DNS y navegador de una persona con
  acceso a la LAN.
- **Superficie:** HTTP/80 en todas las interfaces, hostname mDNS y ausencia de
  validación `Host`/Origin en `src/main.cpp:408-426`.
- **Escenario:** un dominio atacante cambia su resolución a la IP del ESP; el
  navegador trata peticiones posteriores como same-origin y puede leer stats o
  invocar administración.
- **Impacto:** elusión de la protección same-origin y explotación remota mediada
  por el navegador.
- **Probabilidad:** Media; Private Network Access del navegador no es un control
  universal ni estable para el firmware.
- **Severidad:** HIGH.
- **Controles actuales:** P5.2 acepta solo la IPv4 STA actual o
  `c3adblock.local`, con `:80` opcional, antes de login/datos/acciones; rechaza
  controles, otros puertos y hosts arbitrarios, y lo combina con sesión y CSRF.
- **Controles ausentes:** binding explícito a interfaz/subred, validación de
  Origin como defensa adicional y secuencia browser de rebinding/PNA.
- **Corrección propuesta:** conservar la allowlist, probarla con DNS
  público→privado y añadir la restricción de interfaz/canal antes de PILOT.
- **Test necesario:** secuencia DNS público→privado, Host arbitrario/IP/puerto,
  Origin `null`, navegador con y sin PNA y acceso directo legítimo.
- **Condición de aceptación:** un Host u Origin no permitido se rechaza antes de
  servir contenido o mutar estado; rebinding no obtiene JSON ni administración.

### TM-20 — Ausencia de rate limiting

- **ID:** TM-20.
- **Estado P5.3a:** `OPEN`; solo el login recibe throttle RAM creciente. DNS,
  mutaciones y upload manual aún carecen de cuotas generales; fetch está ausente.
- **Activo afectado:** CPU, heap, flash, DNS y disponibilidad del panel.
- **Atacante requerido:** cliente LAN o cliente DNS configurado/comprometido.
- **Superficie:** UDP/53, rutas HTTP y upload manual.
- **Escenario:** ráfagas DNS con upstream caído bloquean hasta 16 esperas de un
  segundo por vuelta; peticiones web o escrituras repetidas no tienen
  cuota por IP ni global.
- **Impacto:** DNS/panel inaccesible, watchdog/reset, desgaste y fragmentación.
- **Probabilidad:** Alta.
- **Severidad:** HIGH.
- **Controles actuales:** presupuesto cooperativo de 16 paquetes por llamada,
  tablas máximas y timeouts parciales. El presupuesto no es rate limiting.
- **Controles ausentes:** token bucket por cliente/global, límites de concurrencia
  y tamaño, backoff, cooldown de flash y métricas de rechazo.
- **Corrección propuesta:** cuotas separadas para DNS, login, mutaciones y upload;
  cortar pronto y mantener turnos para loop/watchdog.
- **Test necesario:** reloj falso para umbral/recarga, IPs múltiples, upstream
  caído, uploads lentos y carga sostenida mientras se consulta salud.
- **Condición de aceptación:** durante diez minutos a dos veces la cuota
  configurada, con upstream de prueba respondiendo en menos de 100 ms, no hay
  reset ni escritura extra; el 99 % de requests administrativos permitidos
  responde en menos de dos segundos y el tráfico excedente recibe rechazo/drop
  según la política sin reducir la cuota de otro cliente.

### TM-21 — Agotamiento y fragmentación de heap

- **ID:** TM-21.
- **Activo afectado:** heap, estabilidad, watchdog y disponibilidad DNS/HTTP.
- **Atacante requerido:** cliente LAN/DNS o uso repetido de los máximos normales.
- **Superficie P5.3a:** 96 `Dev` con `String`, 200 `String` de custom domains,
  JSON por concatenación, HTML del portal y parser multipart HTTP síncrono.
- **Escenario:** entradas largas, campos multipart no-file y ciclos de stats
  fuerzan asignaciones y realocaciones; el heap total puede parecer suficiente
  mientras el mayor bloque libre ya no admite una respuesta JSON.
- **Impacto:** fallo de asignación, respuesta truncada, reset y DNS intermitente.
- **Probabilidad:** Media.
- **Severidad:** HIGH.
- **Controles actuales:** tablas 96/200/32, buffers fijos de 600/1024 bytes y
  exposición de heap libre instantáneo.
- **Controles ausentes:** límites de longitud, serialización streaming, manejo de
  OOM, mínimo histórico/mayor bloque y presupuesto por operación.
- **Corrección propuesta:** validar antes de copiar, evitar concatenaciones
  repetidas, usar buffers acotados/streaming y medir heap mínimo y largest block.
- **Test necesario:** tras diez minutos de warm-up con tablas al máximo, registrar
  cada segundo free heap, minimum free heap, largest free block y el pico de la
  mayor asignación individual (`A_max`); ejecutar 10.000 ciclos stats+DNS y
  uploads adversariales simulados, y repetir la misma muestra final en HIL.
- **Condición de aceptación:** cero resets/OOM; la mediana de free heap y largest
  block de los últimos 60 s no cae más del 5 % respecto a los 60 s posteriores
  al warm-up, y `largest_free_block >= ceil(1,20 * A_max)` en cada muestra.

### TM-22 — Paquetes DNS malformados

- **ID:** TM-22.
- **Activo afectado:** memoria, corrección DNS y disponibilidad.
- **Atacante requerido:** cualquier cliente que pueda enviar UDP/53 al ESP.
- **Superficie:** `parseClientQuery()` en `src/dns_protocol.cpp`, más
  `buildBlocked()` y `handleDns()` en `src/main.cpp`, con buffers acotados a 600
  bytes.
- **Escenario:** un cliente envía header, pregunta, label o terminador truncado;
  QDCOUNT/opcode/QCLASS no soportado; compression pointer; o un datagrama mayor
  que el buffer para provocar lectura parcial, interpretación ambigua o bloqueo
  de `NetworkUDP`.
- **Impacto:** bypass, respuesta incorrecta, agotamiento o loop DNS bloqueado.
  Corrupción de memoria era una hipótesis de P4 y se comprueba ahora con harness
  nativo, no se presupone imposible por inspección.
- **Probabilidad:** Alta; no requiere autenticación.
- **Severidad:** HIGH.
- **Controles actuales:** P6.1 usa un parser C++ compartido y sin Arduino con
  bounds checks antes de cada lectura, una pregunta IN, labels de 1–63 bytes,
  nombre de hasta 253 caracteres, terminación y QTYPE/QCLASS completos. Rechaza
  QR/opcode/QDCOUNT inválidos, pointers en questions, truncado y datagramas
  mayores de 600 B; estos últimos se limpian sin lectura parcial. Una query
  inválida nunca alcanza la decisión de blocklist ni el upstream.
- **Controles ausentes:** DNS sobre TCP, DNSSEC, parsing general de EDNS,
  múltiples preguntas y nombres comprimidos en questions; son límites
  deliberados, no entradas aceptadas parcialmente. CI real y HIL de UDP/carga
  no se han confirmado.
- **Corrección propuesta:** conservar el parser total y fail-closed y no ampliar
  el subconjunto hasta añadir vectores y presupuesto específico.
- **Test necesario:** harness C++ host con corpus de longitudes 0-12, QNAME sin
  cero, labels 63/64, pointers, QDCOUNT 0/2, QR, opcode, clase, EDNS y >600 B;
  fuzzing con ASan/UBSan en host.
- **Condición de aceptación:** todo input inválido tiene resultado determinista y
  no se reenvía. El corpus más un millón de casos con seed `0x4E534D`, máximo 100
  ms/caso y ASan/UBSan termina sin crash, hang, OOB ni sanitizer finding; la seed
  y todo caso que falle quedan guardados como regresión. El job GitHub exacto y
  el HIL en la SuperMini deben confirmarse antes de cambiar el estado a
  `MITIGATED`; cierre exige además carga y compatibilidad del subconjunto.

### TM-23 — Respuestas upstream no asociadas

- **ID:** TM-23.
- **Activo afectado:** autenticidad y corrección de respuestas DNS permitidas.
- **Atacante requerido:** actor capaz de inyectar UDP hacia el puerto efímero o
  respuesta tardía de una consulta anterior.
- **Superficie:** `forwardUpstream()` en `src/main.cpp` y el correlador puro de
  `src/dns_protocol.cpp`.
- **Escenario:** un datagrama falso o tardío compite con Quad9 e intenta hacerse
  pasar por la respuesta de la consulta síncrona actual, o queda en el socket
  para contaminar la consulta siguiente.
- **Impacto:** DNS spoofing, phishing, bloqueo o respuesta cruzada entre clientes.
- **Probabilidad:** Media.
- **Severidad:** HIGH.
- **Controles actuales:** P6.1 mantiene una sola consulta, genera un ID upstream
  separado, conserva el ID cliente y exige origen igual al resolver configurado,
  puerto 53, ID, QR, opcode, QDCOUNT y pregunta QNAME/QTYPE/QCLASS completos.
  Solo entonces restaura el ID cliente. Drena como máximo ocho paquetes stale,
  examina como máximo ocho candidatos y aplica timeout wrap-safe de 1.000 ms.
  Cada paquete inválido/oversized se descarta completo y los retornos de envío se
  comprueban.
- **Controles ausentes:** autenticación criptográfica del DNS UDP, DNSSEC y
  protección contra un atacante on-path que observa la query y puede competir.
  Tampoco existe todavía evidencia HIL del socket real ni CI real confirmada.
- **Corrección propuesta:** mantener la asociación estricta y no aceptar una
  respuesta por ID solamente. DoT/DoH o DNSSEC requerirían una fase y presupuesto
  separados.
- **Test necesario:** upstream UDP falso que primero envíe origen, puerto, ID,
  pregunta y QR incorrectos, además de stale, múltiples candidatos y respuesta
  tardía tras timeout; repetirlo después en HIL con un upstream controlado.
- **Condición de aceptación:** solo una respuesta plenamente asociada se devuelve
  al cliente; las demás se descartan sin contaminar la consulta siguiente. El
  corpus y un millón de mutaciones terminan sin sanitizer finding, GitHub CI se
  confirma para la revisión exacta y HIL demuestra los mismos casos sin reset ni
  starvation sostenida. Hasta entonces permanece `OPEN`, candidata a
  `MITIGATED`.

### TM-24 — Pérdida de Wi-Fi sin recuperación controlada

- **ID:** TM-24.
- **Activo afectado:** disponibilidad DNS, panel, mDNS y updates.
- **Atacante requerido:** no es necesario; reinicio de AP, DHCP o interferencia.
- **Superficie:** `connectWiFi()` en `src/main.cpp:332-345` y loop
  `src/main.cpp:432-441`.
- **Escenario:** solo hay un intento inicial de 20 s; en runtime no existe una
  máquina explícita que reconecte y reinicie UDP/mDNS. Un fallo al boot abre el
  portal, aunque las credenciales fueran correctas.
- **Impacto:** pérdida indefinida de DNS o exposición inesperada del onboarding.
- **Probabilidad:** Media.
- **Severidad:** MEDIUM.
- **Controles actuales:** intento inicial acotado; puede existir auto-reconnect
  del framework, pero no está configurado ni probado como control del producto.
- **Controles ausentes:** estados, backoff, health check, reapertura de sockets,
  distinción entre credencial inválida y fallo transitorio y modo degradado.
- **Corrección propuesta:** máquina de reconexión con backoff máximo, sin portal
  automático; portal solo por onboarding inicial o gesto físico.
- **Test necesario:** mock y HIL de AP reiniciado, DHCP fallido, caída breve/larga,
  credencial errónea y flapping, comprobando DNS/mDNS después.
- **Condición de aceptación:** al volver el AP, DNS se recupera en ≤60 s, con
  cero reinicios inesperados y sin AP cautivo; hashes de blocklist/config antes y
  después son idénticos y los sockets DNS/mDNS vuelven a responder.

### TM-25 — Corrupción y corte durante persistencia

- **ID:** TM-25.
- **Activo afectado:** todos los archivos LittleFS, NVS y estado de arranque OTA.
- **Atacante requerido:** fallo eléctrico, filesystem lleno/desgastado o actor
  que fuerce escrituras repetidas.
- **Superficie:** `saveCustom()`, `saveBanned()`, `saveUpdateCfg()`, swap de
  blocklist y Update en `src/main.cpp:90-124,214-326`.
- **Escenario:** los archivos de texto se sobrescriben directamente y los
  retornos de I/O se ignoran; un corte entre open/write/close/rename deja estado
  parcial o incoherente.
- **Impacto:** pérdida de política, boot inesperado, fail-open o incapacidad de
  recuperar configuración.
- **Probabilidad:** Media durante la vida del dispositivo.
- **Severidad:** HIGH.
- **Controles actuales:** LittleFS, slots duales de app y temporal parcial para
  blocklist; abort de upload elimina el temporal.
- **Controles ausentes:** escrituras copy-on-write para configuración, checksum y
  generación, flush comprobado, journal de boot y tests de corte.
- **Corrección propuesta:** archivos versionados con checksum y commit
  recuperable; comprobar cada I/O y seleccionar la última generación válida al
  boot. No autoformatear.
- **Test necesario:** fault injection tras cada operación y matriz HIL de cortes
  de alimentación en cada fase, incluyendo primer boot de firmware nuevo.
- **Condición de aceptación:** tras cada reinicio existe la versión anterior o la
  nueva completa, nunca datos parciales; corrupción se detecta, no se borra y
  activa un recovery explícito.

### TM-26 — Firmware OTA malicioso o no auténtico

- **ID:** TM-26.
- **Estado P5.1:** `MITIGATED`; no queda entrada de firmware por red y los
  manifests están inertes, pero faltan procedencia/firma USB y confirmar la
  retirada de cualquier despliegue web remoto tras un push autorizado.
- **Activo afectado:** raíz de confianza del firmware, Wi-Fi, DNS y privacidad.
- **Atacante requerido:** cliente LAN que use TM-07/TM-09, servidor de
  distribución comprometido o artefacto sustituido.
- **Superficie:** distribución física/futura del `firmware.bin` y los artefactos
  legacy de auditoría en `docs/` y `netshield-mini/`; los mecanismos Update de
  red están compilados fuera.
- **Escenario:** una imagen estructuralmente válida se acepta sin firma de una
  clave autorizada; un hash no autenticado tampoco prueba procedencia. Los dos
  directorios rastreados publican manifests que apuntan a un firmware anterior
  con `/update`/ArduinoOTA, y sus installers cargan `esp-web-tools@10` desde
  unpkg mediante una referencia móvil sin SRI ni vendoring.
- **Impacto:** código persistente con todos los privilegios del dispositivo.
- **Probabilidad:** Alta mientras las vías actuales estén activas.
- **Severidad:** CRITICAL.
- **Controles actuales:** build reproducible, Actions fijadas por SHA, OTA de red
  ausente, manifests inertes y CI sin publicar firmware. Nada de ello enlaza
  criptográficamente un binario USB recibido con el dispositivo.
- **Controles ausentes:** firma offline, clave pública de confianza, secure boot,
  provenance de artefacto, pin/SRI o vendoring del installer, invalidación de
  binarios stale, verificación antes de marcar bootable y boot confirmation.
- **Corrección propuesta:** P5.1 elimina OTA. Una futura reintroducción exige
  formato/manifest firmado, clave y rotación, verificación streaming y plan de
  recuperación; secure boot/eFuses requieren aprobación humana separada.
- **Test necesario:** imagen válida firmada, byte alterado, firma/clave/manifest
  incorrectos, corte, boot fallido y recuperación; comprobar hashes/manifests,
  ausencia de binario stale y dependencias web fijadas; test de clave revocada.
- **Condición de aceptación:** con OTA deshabilitada no hay entrada por red. Si se
  reintroduce, un slot inactivo puede recibir staging, pero una firma/provenance
  fallida lo invalida: nunca se marca bootable ni arranca; una imagen autorizada
  queda vinculada a la revisión fuente.

### TM-27 — Downgrade de firmware

- **ID:** TM-27.
- **Estado P5.1:** `MITIGATED`; se eliminó el downgrade por red, pero USB/recovery
  aún admite error de operador y no existe versión firmada ni anti-rollback.
- **Activo afectado:** controles de seguridad y formato de datos persistentes.
- **Atacante requerido:** acceso a un canal de update, imagen antigua válida o
  error de operador.
- **Superficie:** `/update`, ArduinoOTA, slots app, manifests/installers rastreados
  y cualquier recovery futuro.
- **Escenario:** se instala una versión antigua con vulnerabilidades conocidas o
  formato incompatible; no hay versión monotónica ni política de rollback.
- **Impacto:** reapertura de vulnerabilidades, corrupción de datos o loop de boot.
- **Probabilidad:** Media.
- **Severidad:** HIGH.
- **Controles actuales:** dos slots facilitan recuperación, pero no distinguen
  downgrade malicioso de rollback legítimo.
- **Controles ausentes:** versión firmada, mínimo aceptado, migración y ventana de
  rollback controlada.
- **Corrección propuesta:** mantener OTA off; si vuelve, firmar versión/build ID,
  rechazar menor que el mínimo y confirmar boot antes de invalidar rollback. El
  anti-rollback por eFuse no se decide sin plan físico y aprobación.
- **Test necesario:** versión igual/mayor/menor, rollback por boot fallido,
  migraciones adelante/atrás y contador corrupto.
- **Condición de aceptación:** una imagen inferior no se instala por red; un
  rollback automático solo vuelve a una imagen conocida, firmada y compatible.

### TM-28 — Exposición accidental desde WAN

- **ID:** TM-28.
- **Activo afectado:** todos los activos administrativos y de red.
- **Atacante requerido:** atacante de Internet y port-forward/DMZ/relay/VPN mal
  configurado por el entorno.
- **Superficie:** HTTP/80 y UDP/53 escuchando en STA, sin restricción por interfaz;
  los servicios OTA de firmware están ausentes. Incluir IPv4/IPv6 según el
  soporte efectivo del build.
- **Escenario:** el router publica el puerto o coloca el ESP en DMZ; un atacante
  remoto usa rutas sin autenticación para tomar el dispositivo.
- **Impacto:** ejecución remota persistente, Wi-Fi comprometida y DNS malicioso.
- **Probabilidad:** Baja, dependiente del router; el impacto no disminuye.
- **Severidad:** CRITICAL.
- **Controles actuales:** el proyecto no configura UPnP, NAT, router ni servicios
  cloud y la política declara que no debe administrarse desde Internet.
- **Controles ausentes:** bind/restricción de subred, autenticación, deny WAN,
  checklist y verificación externa previa al despliegue.
- **Corrección propuesta:** administración local mínima, DNS limitado al segmento
  servido, capacidades peligrosas fuera, filtro de origen y documentación que
  prohíba forwarding, DMZ, exposición cloud y UPnP.
- **Test necesario:** inventario IPv4/IPv6 y escaneo TCP+UDP desde LAN y una
  segunda zona no administrativa en laboratorio; VPN/guest y forward simulado.
- **Condición de aceptación:** en la topología PILOT documentada, el vantage point
  de una segunda zona obtiene cero panel/OTA y UDP/53 no responde como resolver;
  se archivan mapa, IPs, rutas, listeners, NAT/firewall y comando de escaneo. Es
  evidencia de esa instalación, no garantía universal; no se cambia el router.

### TM-29 — Privacidad y retención de consultas

- **ID:** TM-29.
- **Activo afectado:** historial de navegación, identidad IP/MAC y hábitos.
- **Atacante requerido:** administrador no autorizado, firmware comprometido,
  acceso a stats/flash/logs, resolver upstream u observador on-path.
- **Superficie:** `handleDns()`, tabla `clients`, bans/custom, stats y Serial.
- **Escenario:** aunque hoy no se persisten QNAME, futuros logs o métricas podrían
  crear historial; actualmente IP/MAC y contadores de actividad permanecen en
  RAM y algunos IP banned persisten. Cada QNAME permitido se envía por UDP claro
  a Quad9 y resulta visible para ese resolver y observadores de red; los bloqueados
  localmente no se reenvían.
- **Impacto:** perfilado de usuarios y exposición de la topología de la LAN.
- **Probabilidad:** Media.
- **Severidad:** MEDIUM.
- **Controles actuales:** no se guarda el nombre consultado, no hay telemetría ni
  cloud, y los contadores son agregados.
- **Controles ausentes:** TTL de clientes, política verificable de retención,
  minimización/redacción de stats y tests que impidan introducir query logging.
- **Corrección propuesta:** prohibir historial de dominios, expirar clientes
  volátiles tras 15 minutos de inactividad, limitar bans a lo necesario y
  redactar identificadores/logs. Documentar explícitamente el resolver fijo y la
  visibilidad de queries permitidas; no prometer privacidad de transporte.
- **Test necesario:** captura de Serial, NVS, LittleFS y respuestas tras corpus de
  consultas; reboot/TTL/borrado y scan estático de nuevas escrituras de QNAME.
- **Condición de aceptación:** ningún dominio consultado aparece en persistencia,
  logs ni telemetría; cada cliente no banned desaparece tras 15 minutos sin
  tráfico. Una captura confirma que solo QNAME permitidos salen hacia el resolver
  documentado y la persona piloto recibe esa limitación. El factory reset físico
  elimina NVS Wi-Fi, bans, custom y update config, conserva la blocklist base y
  se verifica tras reboot.

### TM-30 — Recuperación física mediante BOOT

- **ID:** TM-30.
- **Estado P5.2a:** `PARTIALLY MITIGATED`; implementación, CI y HIL acordado
  confirmados en `bbeacda`. Quedan pruebas de fallo NVS y recovery USB/FS.
- **Activo afectado:** disponibilidad, credenciales Wi-Fi y capacidad de recuperar
  una unidad no conectada.
- **Atacante requerido:** acceso físico al dispositivo; el fallo también puede
  ser accidental por rebote/strapping.
- **Superficie:** GPIO9, la máquina runtime de `src/main.cpp` y el bootloader ROM
  del ESP32-C3.
- **Escenario:** una pulsación corta, rebote, botón atascado o reinicio mientras
  GPIO9 está LOW podría borrar estado inesperadamente o entrar en el downloader.
  Un fallo al borrar NVS puede producir una falsa expectativa de recuperación;
  un `secrets.h` compilado sigue siendo una vía de conexión alternativa.
- **Impacto:** DoS físico, recuperación incompleta o falsa expectativa de borrado;
  no recupera por sí solo firmware/LittleFS corruptos.
- **Probabilidad:** Baja.
- **Severidad:** MEDIUM.
- **Controles actuales:** `INPUT_PULLUP`; ninguna lectura destructiva en `setup()`;
  liberación observada antes de armar; hold continuo no bloqueante de 3 s en el
  portal y 5 s en STA; HIGH/rebote reinicia el contador. STA zeroiza sesión/CSRF,
  borra Wi-Fi/verificador y espera BOOT HIGH estable antes de reiniciar. El portal
  rota CSRF y permanece activo; el guardado también difiere su reboot hasta HIGH
  estable. BOOT+RESET se documenta solo para downloader ROM.
- **Controles ausentes:** comprobación del resultado de los clears NVS, feedback
  visible fuera de Serial, expiración de la autorización, recovery de
  filesystem/firmware y validación física repetida en la SuperMini exacta.
- **Corrección propuesta:** propagar fallos NVS y no afirmar recuperación si el
  clear falla; limitar temporalmente la autorización; no compilar credenciales
  en PILOT; mantener separados reset Wi-Fi, recovery FS y reflasheo USB autorizado.
- **Test necesario:** GPIO alto, mantenido desde reset, rebote, pulsaciones
  `<3 s`/`>=3 s` en portal y `<5 s`/`>=5 s` en STA, release antes del reboot,
  refresh CSRF sin reboot, fallback secrets, NVS fallida y HIL de modo ROM.
- **Condición de aceptación:** ningún muestreo temprano borra estado; veinte de
  veinte pulsaciones cortas/rebotes conservan claves y veinte de veinte holds
  válidos producen el estado esperado. STA solo reinicia después de release y
  vuelve al portal read-only; el formulario requiere un nuevo hold de 3 s. El
  hash de una restauración USB known-good coincide con el artefacto autorizado.

## Cinco riesgos principales de la baseline P4

Esta lista conserva la priorización que decidió P5.1. El estado actual y sus
riesgos residuales están en «Delta P5.3a»; no debe interpretarse como inventario
de rutas actualmente compiladas.

1. **Ejecución de firmware por red:** `/update`, ArduinoOTA y falta de firma
   (TM-07, TM-09 y TM-26).
2. **Plano administrativo sin identidad:** auth, CSRF, rebinding y posible WAN
   convierten una petición en control total (TM-17 a TM-19 y TM-28).
3. **Cadena de blocklist destructiva/no auténtica:** upload/fetch, swap, TLS y
   SSRF pueden desactivar o sustituir la política (TM-06, TM-08, TM-13 a TM-15).
4. **Entrada no confiable en panel/onboarding:** XSS persistente o por SSID puede
   operar con el origen del dispositivo (TM-10 y TM-16).
5. **Plano DNS y recursos no robustos:** parser, asociación upstream, rate limit
   y heap permiten spoofing o DoS (TM-20 a TM-23).

## Comparación de los candidatos al primer parche P5

Los tamaños siguientes son estimaciones de planificación obtenidas del mapa
actual, no resultados de builds de variantes. Deben confirmarse con dos builds
limpios y comparables. No se suman linealmente porque el linker elimina código
transitivo compartido.

En esta decisión, **A significa las dos vías de firmware OTA por red**:
`/update` y ArduinoOTA. La palabra “OTA” es ambigua en comentarios del código,
que también llaman OTA al upload de blocklist; los caminos de blocklist se
tratan expresamente en C y D y permanecen fuera de PILOT hasta superarlos.

| Opción | Seguridad ganada | Flash/RAM estimados | Complejidad | Superficie y tests | Riesgo de regresión |
| --- | --- | --- | --- | --- | --- |
| **A. Deshabilitar todas las OTA de firmware por red** | Cierra los dos caminos CRITICAL de código arbitrario y corta el vector remoto principal de una imagen no auténtica; la procedencia del flasheo USB sigue siendo un control necesario. | **−18 a −45 KiB flash**; el mapa atribuye 1.956 B de BSS directo a Update/ArduinoOTA/buffer, por lo que se esperan **−1,9 a −2,5 KiB de RAM estática**; el ahorro dinámico no está medido. | Baja-media. Es eliminación de código y UI. | `/update`, `Update`, ArduinoOTA, loop, servicio, formulario e installers stale. Builds, símbolos/strings/map/hash, 404/405 HIL y regresión DNS/panel. | Se pierden OTA e installer web hasta regenerarlo; recuperación/actualización quedan por USB con aprobación humana. |
| **B. Añadir autenticación al panel** | Reduce la toma general de TM-01/TM-18, pero HTTP no da confidencialidad y XSS/CSRF pueden eludir una sesión mal diseñada. | **+3 a +15 KiB flash**; +0,1 a 1 KiB estática y +1 a 5 KiB dinámica, según KDF/sesión. | Alta: provisión, almacenamiento, expiración, lockout y recovery. | Todas las rutas, cookie/header, reboot, lockout, recuperación y logs. | Lockout del dueño, credenciales observables por HTTP y clientes/scripts rotos. |
| **C. Blocklist transaccional, acotada y validada** | Protege integridad/disponibilidad de política y evita fail-open de TM-06/TM-13. | **+2 a +10 KiB flash** y menos de 1 KiB RAM si valida en streaming; el coste de firma/manifest sigue sin estimar. | Muy alta por la capacidad física: no caben live+staging para las listas actuales máximas. | FS abstraído, límites/orden/digest, todos los fallos de I/O, reboot y power-cut HIL. | Updates reales pueden rechazarse por falta de espacio; no se permite borrar live para “resolverlo”. |
| **D. Eliminar HTTP y `setInsecure()`** | Mitiga MITM/downgrade solo si cadena, hostname, tiempo y redirects se validan; también debe cerrar SSRF. | Transporte con CA mínima/host fijo: **+2 a +15 KiB flash** estimados. La sección del bundle completo mide 68.987 B, pero su delta enlazado no está medido. Firma/manifest tienen coste desconocido. El pico dinámico TLS tampoco está medido. | Alta: hora, CA rotation, host, redirects, tamaño y autenticidad. | HTTP/cert/hostname/reloj/redirect/SSRF/timeouts y firma/provenance con clientes simulados. | Fetch roto por reloj, CA/CDN o redirect; fallback inseguro queda prohibido. Deshabilitar fetch en vez de conservarlo ahorraría flash. |
| **E. Corregir XSS y validar entradas** | Cierra cadenas prácticas de panel/portal y reduce heap; es precondición de una auth útil. | **+2 a +12 KiB flash**; 0 a 1 KiB estática, con posible ahorro dinámico por límites. | Media-alta por los contextos JSON, HTML, atributo, DOM, DNS, SSID y URL. | Payloads table-driven, bordes DNS/SSID/URL, datos legacy y navegador automatizado. | Rechazo de entradas antes toleradas y regresiones de UI/onboarding. |

### Decisión: P5.1 será A

P5.1 debe crear perfiles/gates explícitos, hacer que CI compile y mida ambos, y
retirar de ambos, sin feature flag distribuible:

1. `#include <Update.h>`, handlers y registro de `/update`;
2. `#include <ArduinoOTA.h>`, `begin()`, `handle()` y servicio asociado;
3. el formulario y JavaScript de firmware OTA del panel;
4. textos/logs que afirmen que OTA está disponible;
5. gates separados para panel admin, blocklist upload y fetch, todos fail-closed
   y apagados por defecto hasta el parche que los habilite;
6. deshabilitar los installers rastreados y retirar sus manifests/binarios stale,
   o regenerarlos desde el build P5.1 con hash/provenance; una dependencia web
   futura debe fijarse por contenido/SRI o quedar vendorizada.

No cambia `partitions.csv`: los dos slots se conservan por compatibilidad y para
una futura OTA firmada, no como rollback ya implementado. P5.1 no implementa C/D
ni presenta blocklist update como seguro. Upload/fetch quedan apagados en
DEVELOPMENT salvo un build de prueba deliberado después de su gate; PILOT exige
P5.2-P5.5 para upload y P5.2-P5.6 para fetch.

La elección maximiza reducción inmediata porque elimina código ejecutable no
autenticado y además **libera** flash/RAM, creando presupuesto para E y B. B por
sí sola deja dos protocolos, XSS/CSRF y firmware sin firma; C/D no eliminan la
ejecución de firmware; E reduce una cadena indirecta pero no las cargas binarias
directas. El riesgo de regresión de A está acotado a la pérdida deliberada de
update remoto y se mitiga con reflasheo/restauración USB known-good documentado.

## Prioridad de implementación

ADR-004 conserva la secuencia original como decisión histórica. La petición
P5.2 de 2026-08-08 sustituye sus tres entregas separadas P5.2-P5.4 por una sola
candidate coherente: XSS/encoding, autenticación, sesión, métodos, CSRF, Host y
throttle de login se introducen juntos. Esto no da por resuelto el canal HTTP ni
el rate limiting general.

| Orden | Parche | Amenazas principales | Gate |
| --- | --- | --- | --- |
| **P5.1** | Retirar `/update`, ArduinoOTA y UI | TM-07, TM-09, TM-26 | Committed en `dce4672`; CI verde confirmada y HIL funcional completado. |
| **P5.2** | Panel combinado: encoding/DOM, PBKDF2, BOOT, sesión, POST+CSRF, Host, headers y throttle login | TM-01, TM-02, TM-16 a TM-20 | Host/build y después browser/HIL; HTTP claro mantiene PILOT en NO-GO. |
| **P5.3/P5.4 originales** | Absorbidos por P5.2 para controles de código; quedan canal, interfaz, Origin/reautenticación y rate limit general | TM-01, TM-17 a TM-20, TM-28 | No se declaran completos por añadir auth sobre HTTP. |
| **P5.3a** | C parcial: blocklist manual last-known-good, límites, validación, recovery y fetch eliminado | TM-06, TM-08, TM-12 a TM-15, TM-25 | Implementado localmente; upload sigue fuera de PILOT hasta CI/HIL, autenticidad y capacidad real. |
| **P5.5** | Procedencia ECDSA para nuevos uploads, proof temporal y recovery autenticado | TM-06, TM-13 | V1 mantiene replay y listas legacy unsigned; requiere CI y HIL multipart/power-cut y no resuelve HTTP claro. |
| **P5.6** | D: transporte HTTPS verificado, redirects y política SSRF; la firma P5.5 seguiría siendo obligatoria | TM-08, TM-14, TM-15 | Fetch remoto sigue compilado fuera si el coste/ciclo CA no es aceptable. |
| **P5.7** | Portal físico/temporal, NVS/FS endurecidos, reconexión y recovery probado | TM-10 a TM-12, TM-24, TM-25, TM-30 | Bloqueante de PILOT. |
| **P5.8** | Parser DNS, asociación upstream, cuotas y presupuesto de heap | TM-20 a TM-23 | Bloqueante de PILOT y requiere fuzz/HIL. |
| **P6.1** | Subconjunto P5.8: parser DNS acotado, ID separado y asociación upstream estricta | TM-22, TM-23 | Implementación y harness host; CI ASan/UBSan real y HIL con upstream controlado pendientes. |
| **P5.9** | Firma, boot confirmation y anti-downgrade si se decide reabrir OTA | TM-26, TM-27 | Opcional para PILOT solo si OTA permanece ausente; obligatorio para reactivarla. |
| **P5.10** | Redacción de logs, privacidad, expiración, soak y checklist anti-WAN | TM-02, TM-28, TM-29 | Cierre de gate PILOT. |

## Perfiles objetivo

Los perfiles son políticas de uso y gates; todavía no constituyen variantes de
build completas y separadas.

### DEVELOPMENT

Utilizable únicamente en nuestra LAN de pruebas:

- una placa y clientes controlados, segmento aislado, sin usarlo como DNS de un
  hogar ni procesar tráfico personal;
- sin port-forward, DMZ, relay cloud ni administración WAN; el firmware no
  cambia router, DNS, DHCP ni Wi-Fi;
- OTA de firmware siempre compilada fuera después de P5.1;
- upload manual de blocklist solo detrás de auth/CSRF, con proof de la autoridad
  aprobada y ejercitado en pruebas deliberadas; fetch, URL e intervalo remotos
  están ausentes. El upload no está permitido en PILOT;
- antes de P5.10, solo SSID de laboratorio deliberadamente no sensible; nunca
  password, token, QNAME ni bypass;
- assertions y nombre de perfil visibles para impedir confundirlo con PILOT;
- recuperación física/USB documentada. Flasheo y puerto serie siguen requiriendo
  aprobación humana independiente.

Este perfil acepta temporalmente HTTP claro y otros riesgos HIGH solo por
aislamiento, presencia física y control de clientes. No los convierte en seguros
ni aptos para terceros.

### PILOT

Mínimo antes de instalarlo a otra persona:

- perfil predeterminado y fail-closed, sin bypass de desarrollo;
- OTA de firmware compilada fuera, salvo que P5.9 completo sea aprobado;
- la candidate P5.2 autentica y protege de CSRF/rebinding a nivel de aplicación,
  pero administración permanece ausente/read-only para PILOT hasta proteger el
  canal y pasar browser/HIL;
- upload manual ausente/read-only para PILOT hasta completar CI, HIL
  transaccional y una decisión explícita sobre replay/legacy; fetch remoto
  permanece compilado fuera sin fecha de reapertura;
- una administración sobre HTTP claro no se aprueba solo por añadir password:
  debe estar ausente/limitada a una ventana física o usar un canal que proteja
  credencial y sesión; aceptar HTTP deja un HIGH residual explícito;
- portal solo por onboarding/recuperación física, temporal y protegido;
- ningún `setInsecure`, HTTP remoto, URL arbitraria, autoformato o query history;
- parser/asociación DNS, reconexión, cuotas, heap y recuperación probados en la
  placa exacta;
- logs mínimos y política de privacidad/soporte entregada a la persona piloto.

## Plan de pruebas requerido

### Host y CI, sin hardware ni Internet

- mantener los 67 resultados pytest de la baseline anterior a P5.2;
- P5.2 añade 32 gates de KDF/NVS, bootstrap físico fail-closed, sesión/cookie,
  CSRF, throttle, Host, matriz de rutas/métodos, escape/DOM/CSP y regresión
  OTA/RF/archivos protegidos; la suite local completa termina con 99 aprobados;
- añadir harness C++ nativo para validadores, parser DNS, serialización JSON y
  asociación de respuestas;
- P6.1 implementa el primer harness C++ sobre el mismo parser/correlador de
  producción: 100.000 mutaciones ASan en Windows y un job Linux preparado para
  1.000.000 con ASan/UBSan y seed `0x4E534D`; la ejecución GitHub sigue
  pendiente;
- ampliar después el harness nativo a serialización JSON y otros validadores;
- adapters falsos para LittleFS, NVS, HTTP, reloj y Wi-Fi con fault injection;
- tests DOM en HTML local para payloads XSS y matriz de rutas/métodos/auth/CSRF;
- builds limpios DEVELOPMENT y PILOT, inspección de ELF/map/strings, tamaño de
  `firmware.bin`, RAM, diff check, secretos y archivos protegidos;
- gate de artefactos: manifests solo apuntan al hash/build autorizado, no quedan
  binarios stale y toda dependencia del installer está fijada por contenido;
- mocks HTTP locales: ningún test descarga blocklists o firmware de Internet.

### HIL posterior, siempre con aprobación humana

- P5.2: BOOT y alta/reset admin; login, throttle, sesión/logout/expiración/reboot;
  Host IP/mDNS/puerto/rebinding; CSRF/métodos; corpus XSS en navegador y heap de
  PBKDF2;
- ausencia de `/update` y servicio ArduinoOTA; regresión DNS/panel;
- P6.1: upstream UDP controlado con respuesta válida, origen/puerto/ID/pregunta
  falsos, stale, timeout y ráfaga; A/AAAA, queries bloqueadas sin upstream,
  disponibilidad de panel/BOOT y heap mínimo;
- carga DNS y pérdida/reconexión Wi-Fi;
- onboarding hostil con SSID malicioso, timeout y presencia física;
- blocklist real dentro del máximo transaccional y cortes de alimentación en
  cada fase de escritura/boot;
- BOOT, ROM downloader y recuperación USB en la SuperMini exacta;
- 24 horas de estrés y siete días de soak sin resets, corrupción ni tendencia de
  heap; captura de logs/persistencia para privacidad;
- escaneo desde otra subred/WAN simulado solo en laboratorio autorizado.

## Impacto esperado en flash y RAM

| Estado/parche | Flash esperado | RAM esperada |
| --- | --- | --- |
| P4 (este documento) | 0 bytes de firmware | 0 bytes runtime |
| Baseline P3 | 1.298.656/1.376.256 B; 77.600 B libres | 53.124/327.680 B estáticos |
| P5.1 `dce4672` medido | 1.274.960/1.376.256 B; 101.296 B libres; 1.234.851 B enlazados | 51.164/327.680 B; ahorro dinámico no medido |
| P5.2 combinado, medido localmente | 1.291.104/1.376.256 B físicos; 85.152 B (83,16 KiB) libres; 1.249.513 B enlazados | 51.292/327.680 B estáticos; pico PBKDF2 aún debe medirse en HIL |
| P5.3a manual-only, medido localmente | 1.160.704/1.376.256 B físicos; 215.552 B libres; 1.122.703 B enlazados | 50.684/327.680 B estáticos; heap dinámico pendiente de HIL |
| P5.5 procedencia de blocklist, medido localmente | 1.165.808/1.376.256 B físicos; 210.448 B libres; 1.127.265 B enlazados | 50.828/327.680 B estáticos; pico ECDSA/FS pendiente de HIL |
| P6.1 parser/correlación DNS, medido localmente | 1.168.720/1.376.256 B físicos; 207.536 B libres; 1.129.779 B enlazados | 51.420/327.680 B estáticos; dos buffers globales acotados de 600 B; stack/heap dinámico pendientes de HIL |
| P5.6 D | transporte +2 a +15 KiB con CA mínima; sección bundle 68.987 B, delta real y coste firma desconocidos | pico dinámico TLS no medido hasta HIL |

No se inventa todavía un límite comercial adicional al slot físico. Cada parche
debe medir `firmware.bin`, flash reportada, RAM estática, heap mínimo y mayor
bloque libre; si el margen disminuye, se detiene la siguiente función hasta una
revisión humana. Los rangos anteriores no son criterios de éxito.

## Criterios para el primer flash de laboratorio

El primer flash solo se permite después de P5.1 y de aprobación humana explícita:

1. P5.1 revisado: `/update`, ArduinoOTA y su UI/símbolos están ausentes en ambos
   perfiles; installers/manifests no ofrecen el binario anterior. Ambos conservan
   build e inspección estática. El smoke DNS/panel es HIL posterior, porque P4
   confirma que no existe harness de firmware.
2. `pytest`, Ruff, diff check y builds limpios pasan; el humano confirma verdes
   ambos jobs GitHub para la revisión exacta si ya se ha hecho push autorizado.
3. `partitions.csv` y `LICENSE` intactos; `src/secrets.h` no rastreado; cero
   credenciales reales en fuente, binario compartido, tests o logs. Solo se usa
   un SSID de laboratorio no sensible, no se configura URL y no se captura Serial.
4. SHA-256, commit fuente, toolchain, tamaño físico, RAM y mapa del binario quedan
   registrados. El margen físico no es menor que 77.600 B y debe medirse, no
   inferirse del rango estimado; si P5.1 no lo aumenta o queda fuera de su rango,
   se investiga y documenta antes del flash.
5. Blocklist local pequeña y validada; no se configura URL remota ni se usa una
   blocklist descargada durante tests.
6. Reflasheo/restauración manual por USB de una imagen known-good, con hash y
   procedencia, documentado antes de retirar OTA; no se presupone rollback.
7. Placa propia, LAN aislada y clientes controlados; no es DNS de producción y
   se verifica que no existe exposición WAN, sin cambiar el router en esta tarea.
8. Flashear y abrir cualquier COM requieren aprobaciones separadas; P4 no realiza
   ni presupone esas acciones.

Aunque se cumplan, DEVELOPMENT conserva amenazas CRITICAL/HIGH documentadas y no
se instalará a terceros.

Estado de P5.1: el primer HIL de laboratorio ya se realizó con autorización
humana explícita. La persona confirmó CI verde y validó SoftAP, DHCP, portal,
persistencia, STA, dashboard y DNS; la prueba RF estableció 8,5 dBm para la
SuperMini ensayada. Esto habilitó DEVELOPMENT controlado, no PILOT.

Estado de la candidate P5.2: pytest, Ruff, diff check, build y tamaño/hash pasan
localmente, pero sigue en **NO-GO para flash** hasta revisión humana y pruebas
de navegador/HIL. Cualquier flash requerirá otra autorización humana específica;
este documento no la concede.

## Criterios más estrictos para PILOT

1. Cero amenazas CRITICAL abiertas. Ninguna HIGH sin control compensatorio,
   responsable, fecha y aceptación humana escrita.
2. P5.2 combinado, P5.5-P5.8 y P5.10 son obligatorios para el núcleo
   DNS/onboarding/recovery, además de cerrar los residuos de canal/rate limit que
   el plan original asignaba a P5.3/P5.4.
   Solo panel admin, upload, fetch y OTA pueden omitirse compilándolos fuera;
   P5.9 se omite únicamente si toda OTA de firmware permanece ausente.
3. Ambos perfiles pasan host tests, fuzzing, build y CI real confirmada por el
   humano. HIL completo usa el binario PILOT exacto; DEVELOPMENT recibe smoke
   diferencial en la misma revisión y toolchain.
4. Auth/CSRF/rebinding/rate limit y un canal que proteja credencial/sesión están
   activos, o el panel administrativo está ausente; portal temporal con presencia
   física y recovery probado. HTTP claro con password conserva un HIGH abierto.
5. Update manual de blocklist conserva last-known-good tras cada fallo y corte
   con un tamaño real que quepa; si no, queda ausente/read-only. El fetch remoto
   permanece ausente.
6. No existe HTTP remoto, `setInsecure`, SSRF ni URL arbitraria. Ningún canal de
   firmware por red funciona sin firma; el reflasheo USB exige hash, provenance y
   revisión humana, aunque P5.9 se omita.
7. Parser y asociación DNS pasan corpus/fuzz; upstream caído y carga no reinician
   el equipo ni bloquean indefinidamente panel/watchdog.
8. Pruebas de 24 h de estrés y siete días de soak: cero resets inesperados,
   corrupción, pérdida sostenida de DNS o degradación de heap fuera del criterio
   de TM-21.
9. BOOT y USB recuperan credenciales, FS/firmware según el procedimiento; eFuses,
   flash encryption o secure boot no se escriben sin plan y aprobación propios.
10. Privacidad, retención, actualización, soporte y no exposición WAN están
    documentados; el instalador registra build/hash y la persona piloto conoce
    las limitaciones. No se promete bloqueo total, antivirus ni anonimato.

PILOT sigue sin equivaler a producto seguro o auditado; es el mínimo para una
prueba limitada con consentimiento y monitorización.
