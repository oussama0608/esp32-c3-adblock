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

## ADR-002 — Generador de blocklist validado y atómico

- Fecha: 2026-08-06
- Estado: accepted
- Contexto: el generador escribía directamente sobre el destino y trataba el
  fallo de todas las fuentes como una blocklist vacía correcta. Su validación
  aceptaba entradas que no eran nombres DNS y no existían tests automatizados
  para proteger el formato consumido por el firmware.
- Decisión: mantener sin cambios FNV-1a de 64 bits truncado a 40 bits, los cinco
  bytes little-endian, el orden numérico y la deduplicación de hashes. Validar
  nombres ASCII con al menos dos labels, máximo total de 253 caracteres, máximo
  de 63 por label, caracteres LDH y rechazo de literales IP. Fallar si ninguna
  fuente es legible o si no queda ningún dominio válido. Limitar por defecto el
  blob a 1.250.000 bytes, equivalente al presupuesto existente de 250.000
  hashes, y permitir reducir o ajustar el límite con `--max-bytes`.
- Escritura: construir y validar el blob completo en memoria; después escribir
  un temporal en el mismo directorio, hacer `flush` y `fsync`, cerrar el handle
  y sustituir el destino con `os.replace`. Ante cualquier fallo previo al
  reemplazo, conservar el destino y limpiar el temporal.
- Tests: usar fixtures locales deterministas, impedir Internet por defecto y
  simular la única descarga HTTP. Cubrir normalización, validación DNS, vectores
  de hash, serialización, orden, duplicados, colisiones, límites y rutas de fallo
  y reemplazo.
- Alternativas: añadir cabecera, checksum o metadatos al blob mejoraría su
  autodescripción, pero rompería el formato de producción y queda descartado en
  P2. Escribir un blob vacío al fallar las fuentes también queda descartado
  porque confunde fallo con éxito y puede destruir una blocklist válida.
- Consecuencias: una fuente fallida todavía puede omitirse si otra fuente válida
  permite completar el build, y el error queda visible en stderr. Los IDN deben
  llegar en punycode; Unicode directo se rechaza. Las colisiones se cuentan y se
  reportan, pero siguen provocando sobrebloqueo en vez de abortar. La sustitución
  atómica depende de que el destino esté en un filesystem local que implemente
  correctamente `os.replace`; un corte de energía requiere validación de
  hardware posterior.
- Verificación: 47 casos pytest pasan también con Python 3.13 y Ruff no reporta
  infracciones. No se modifican `partitions.csv`, `LICENSE` ni el formato
  binario del firmware.

## ADR-003 — CI mínima, reproducible y sin privilegios

- Fecha: 2026-08-07
- Estado: accepted
- Contexto: P2 incorporó tests deterministas y recuperó un build local
  verificable, pero cada push y pull request seguía sin gates automáticos para
  calidad Python, firmware, tamaño físico, archivos protegidos o secretos.
- Decisión: crear `.github/workflows/ci.yml` para pushes y pull requests a
  `main` y `develop`, más `workflow_dispatch`, con permisos globales limitados a
  `contents: read`. Usar dos jobs independientes en `windows-2022`, timeouts
  explícitos y checkout sin persistir credenciales. No usar GitHub Secrets,
  upload, monitor, artefactos, release ni deployment.
- Supply chain: usar únicamente `actions/checkout` 6.0.2 en
  `de0fac2e4500dabe0009e67214ff5f5447ce83dd` y `actions/setup-python` 6.2.0 en
  `a309ff8b426b58ec0e2a45f0f869d46889d02405`. Ambos SHA se resolvieron desde
  sus tags mediante `git ls-remote` contra los repositorios oficiales
  `github.com/actions/checkout` y `github.com/actions/setup-python`, y se
  comprobaron sus páginas de commit oficiales. No se usan referencias móviles.
- Calidad: fijar Python 3.13.12, pytest 9.1.1 y Ruff 0.16.0. Ejecutar las 47
  pruebas locales sin descargar blocklists, Ruff, comprobaciones de whitespace,
  invariantes del repositorio e inspección estructural del workflow.
- Firmware: fijar Python 3.13.12 y PlatformIO Core 6.1.19, mantener sin cambios
  la plataforma pioarduino 55.03.37 de P1, ubicar `PLATFORMIO_CORE_DIR` en el
  workspace, generar una blocklist solo desde fixtures y ejecutar `pio run`.
  Medir el archivo `firmware.bin` real y fallar si supera cualquiera de los
  slots app de 1.376.256 bytes, sin añadir un límite comercial distinto.
- Integridad: fijar los blobs Git aprobados de `partitions.csv` y `LICENSE`,
  validar los tamaños `app0` y `app1`, exigir una licencia presente y no vacía,
  rechazar `src/secrets.h` rastreado y buscar indicadores obvios de secretos
  únicamente en archivos de texto versionados. Los hallazgos muestran
  categoría, ruta y línea, nunca el posible valor secreto.
- Alternativas: se descartan tags móviles de Actions, scanners cloud o pesados,
  caché innecesaria y publicación del firmware. No usar caché evita una tercera
  Action y hace que la corrección dependa solo de un build limpio, a costa de
  mayor duración y descargas repetidas del toolchain fijado.
- Consecuencias: la preparación del runner requiere acceso a GitHub, PyPI y los
  paquetes de compilación fijados, aunque pytest no descarga blocklists. La
  imagen `windows-2022`, las dependencias transitivas de pip y la disponibilidad
  externa no son inmutables. El escaneo de secretos es heurístico y Windows
  Server 2022 no reproduce exactamente Windows 10 ni sustituye hardware real.
- Verificación: los comandos, gates y estructura YAML se validan localmente.
  El workflow no se considera aprobado para una revisión hasta que una persona
  confirme su ejecución remota. Para `dce4672`, esa confirmación existe y los
  jobs `python-quality` y `firmware-build` quedaron verdes.

## ADR-004 — Threat model y secuencia de hardening previa al piloto

- Fecha: 2026-08-07
- Estado: accepted
- Implementación: P5.1 committed en `dce4672`; CI verde confirmada por una
  persona y HIL funcional end-to-end completado
- Contexto: tras P1-P3 el build y las verificaciones de desarrollo son
  reproducibles, pero el firmware mantiene administración HTTP sin identidad,
  dos vías de firmware OTA sin autenticidad, actualización destructiva de
  blocklist, onboarding abierto y un plano DNS sin harness/fuzz/HIL. El binario
  físico ocupa 1.298.656 de 1.376.256 bytes (94,36 %) y deja 77.600 bytes, por lo
  que el primer control debe reducir riesgo sin consumir el margen restante.
- Modelo: registrar en `docs/THREAT_MODEL.md` treinta amenazas con activo,
  atacante, superficie, escenario, impacto, probabilidad, severidad, controles,
  corrección, test y aceptación. La baseline suma 5 CRITICAL, 20 HIGH, 5 MEDIUM
  y 0 LOW. No se declara el firmware seguro ni apto para piloto.
- Decisión P5.1: seleccionar A y retirar sin feature flag las dos OTA de
  **firmware** por red: `/update` y ArduinoOTA, incluidos handlers, setup/loop y
  UI. Los installers activos quedan deshabilitados y sus manifests inertes; los
  binarios stale se conservan sin cambios solo para auditoría. Blocklist no se
  incluye en A: upload exige P5.2-P5.5 y fetch P5.2-P5.6.
- Tamaño medido: dos builds limpios con el mismo Core 6.1.19 y plataforma
  55.03.37 comparan 1.298.656 B/53.124 B RAM antes con 1.274.224 B/51.164 B RAM
  después. P5.1 ahorra 24.432 B físicos (1,8813 % de la baseline), 20.734 B de
  flash enlazada y 1.960 B de RAM estática. El margen sube de 77.600 a 102.032 B;
  el ahorro dinámico no se ha medido.
- Perfiles: la retirada de OTA es incondicional en el entorno `c3`, de modo que
  ninguna variante construida desde este código puede reactivarla por flag.
  DEVELOPMENT solo puede usarse en nuestra LAN aislada, sin tráfico personal ni
  DNS de producción. PILOT sigue siendo un perfil objetivo futuro y no está
  habilitado; OTA de firmware permanecerá ausente hasta un diseño firmado y
  anti-downgrade separado.
- Secuencia: P5.2 corrige validación/XSS antes de introducir credenciales; P5.3
  añade autenticación/autorización; P5.4 métodos/CSRF/rebinding/rate limit y
  canal admin protegido o ventana física (password sobre HTTP no basta); P5.5
  hace recuperable la blocklist; P5.6 decide HTTPS/autenticidad/SSRF; P5.7
  endurece portal/NVS/FS/Wi-Fi/BOOT; P5.8 DNS/UDP/heap; P5.9 solo reabre OTA con
  firma/anti-downgrade; P5.10 cierra redacción de logs, privacidad, soak y WAN.
- Restricción de blocklist: LittleFS tiene 1.376.256 bytes y el máximo P2 es
  1.250.000 bytes. No caben live y staging al máximo. Incluso dos listas de
  725.035 bytes exceden la partición antes de metadatos. Sin cambiar particiones,
  un update que no pueda preservar last-known-good se rechaza o sigue apagado.
- Restricción TLS: la sección de entrada del bundle CA completo, descartada hoy,
  mide 68.987 bytes. Incorporarla íntegra consumiría aproximadamente esa cantidad
  y dejaría en torno a 8.613 bytes antes de código extra; el delta real requiere
  build. D usa raíz mínima/host restringido o deja fetch off, nunca HTTP/insecure.
- Alternativas: B no se elige primero porque añade estado/credenciales sobre una
  UI con XSS/CSRF y no autentica firmware; C y D no eliminan las cargas de código
  arbitrario; E reduce cadenas indirectas pero no `/update` ni ArduinoOTA. No se
  usa el slot OTA como staging de blocklist ni se cambia `partitions.csv`.
- Consecuencias: P5.1 obliga a reflashear/restaurar manualmente por USB una imagen
  known-good, con hash/procedencia y aprobación
  humana, cierra los dos caminos CRITICAL de firmware por red, reduce el vector
  remoto de imagen no auténtica y crea margen para controles posteriores. La
  procedencia del binario USB todavía debe verificarse. DEVELOPMENT conserva
  riesgos altos y no es un perfil de distribución. PILOT requiere cero CRITICAL
  y HIL/fuzz/soak documentados.
- Verificación P4: inspección estática del código, artefactos, mapa y binario;
  build y diff checks locales. Pytest/Ruff no se pudieron repetir porque no están
  instalados en el entorno local. No se implementó parche, no se flasheó, no se
  abrió ningún puerto serie y no se cambió red, `partitions.csv` ni `LICENSE`.
  En esa revisión P4, la CI remota seguía condicionada a confirmación humana; la
  confirmación posterior de `dce4672` se registra en la verificación P5.1.
- Verificación P5.1: la baseline limpia anterior a P5.2 tiene 67 tests host; el
  build de `dce4672` no enlaza
  ArduinoOTA/Update y el escaneo de binario, ELF y mapa no encuentra sus símbolos,
  handlers ni strings de firmware OTA. La única cadena `/update...` restante es
  `/update.cfg`, propia de blocklist. La clean candidate mide 1.274.960 B
  físicos y tiene SHA-256
  `BA22CE059C06CD86FBBFA5D1411261C85533DB22F92C4A555E83235F5637FA9E`.
  Una persona confirmó ambos jobs de CI verdes. El HIL end-to-end validó SoftAP,
  DHCP, portal, persistencia, STA, panel y DNS, y justificó limitar a 8,5 dBm la
  placa SuperMini ensayada. Eso no cierra los riesgos posteriores ni generaliza
  el workaround RF a todos los ESP32-C3.

## ADR-005 — Seguridad del panel administrativo local

- Fecha: 2026-08-08
- Estado: accepted
- Contexto: P5.1 eliminó las vías de firmware OTA por red y liberó margen, pero
  el dashboard y sus mutaciones seguían sin identidad, sesión, CSRF, allowlist de
  `Host` ni codificación por contexto. ADR-004 separaba esos controles entre
  P5.2, P5.3 y P5.4. La entrega P5.2 autorizada los combina para evitar añadir
  primero una credencial sobre una UI que todavía pudiera ejecutar contenido no
  confiable. Esta decisión sustituye esa secuencia para la entrega actual, sin
  reescribir la decisión histórica de ADR-004 ni adelantar el hardening de
  blocklist, TLS/SSRF, filesystem o DNS.
- Verificador: usar únicamente mbedTLS ya incluido por ESP-IDF, con
  PBKDF2-HMAC-SHA-256, 50.000 iteraciones, salt aleatorio de 16 bytes y
  verificador de 32 bytes. Aceptar contraseñas de 12 a 128 bytes, sin valor por
  defecto. NVS, en el namespace `admin`, guarda solo versión, iteraciones, salt y
  verificador. Las comparaciones usan una primitiva constant-time y los buffers
  sensibles se limpian después de usarlos.
- Bootstrap y recuperación: crear o sustituir el verificador únicamente dentro
  de una ventana de provisioning autorizada manteniendo BOOT tres segundos con
  el portal y el firmware ya en ejecución. Una pulsación de cinco segundos en
  modo STA borra Wi-Fi, verificador y sesión, espera a que BOOT se libere y
  reinicia al portal bloqueado; allí sigue siendo necesario el gesto de tres
  segundos. BOOT debe estar libre durante reset/power-on porque GPIO9 también es
  un pin de strapping; esa secuencia ROM no es autorización de provisioning. La
  ausencia o corrupción del registro falla cerrada: no crea una credencial
  conocida ni permite administración anónima. No existe reset remoto de la
  contraseña. El AP cautivo de esa ventana continúa abierto y sobre HTTP por
  compatibilidad con el onboarding actual; es un riesgo DEVELOPMENT explícito y
  un bloqueo de PILOT.
- Sesión: mantener una sola sesión administrativa de 30 minutos. Token de sesión
  y token CSRF independientes, de 32 bytes cada uno, se generan mediante el RNG
  del ESP y permanecen solo en RAM. Un login correcto reemplaza la sesión
  anterior; logout, expiración y reboot la invalidan. La cookie se limita con
  `HttpOnly`, `SameSite=Strict`, `Path=/` y `Max-Age=1800`. No se usa `Secure`
  mientras el dispositivo sea HTTP-only, porque el navegador no la devolvería;
  esta omisión no aporta confidencialidad y permanece como riesgo abierto.
- Throttle: los dos primeros fallos no añaden bloqueo; el tercero bloquea cinco
  segundos, el cuarto diez, el quinto veinte y los siguientes treinta. El estado
  vive solo en RAM y un login correcto o un reboot lo restablecen, evitando un
  lockout persistente.
- Autorización y CSRF: en modo STA solo `GET /login` y `POST /login` son públicos.
  `GET /`, `GET /app.js` y `GET /stats.json` exigen sesión. `POST /logout`,
  `/ban`, `/addblock`, `/unblock`, `/forgetwifi`, `/upload`, `/fetchnow` y
  `/setupdate` exigen además un token CSRF ligado a la sesión. Las mutaciones no
  se registran con GET. El portal es un plano separado: su formulario solo se
  sirve en modo provisioning y `/wifisave` exige POST, autorización física y su
  token aleatorio propio. `/update` de firmware permanece ausente.
- Rebinding: antes del login y de cualquier contenido administrativo se acepta
  únicamente la IPv4 STA actual o `c3adblock.local`, opcionalmente con `:80`.
  Hosts vacíos, malformados, con controles, otro puerto o cualquier nombre
  arbitrario reciben 403. No se construyen redirects desde el valor de `Host`.
  El comportamiento catch-all del portal se mantiene separado porque los probes
  cautivos usan hosts ajenos; su capacidad de mutación queda limitada por la
  presencia física y el token de provisioning.
- XSS y headers: codificar `&`, `<`, `>`, `"` y `'` en contextos HTML y aplicar
  escape JSON completo para controles, comillas y backslash. El dashboard crea
  nodos con APIs DOM seguras y listeners, sin insertar valores no confiables como
  HTML o JavaScript. Servir el script como recurso propio y añadir
  `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer` y una CSP con scripts solo `self`, sin objetos,
  bases ni frames. `style-src 'unsafe-inline'` se conserva por el CSS existente;
  no se añade HSTS a un servicio HTTP.
- Logs y entrada: la raíz no autenticada redirige únicamente a la ruta fija
  `/login` después de validar `Host`. El build falla si Arduino core se compila
  en nivel `VERBOSE`, ya que `WebServer` contiene trazas que pueden imprimir los
  cuerpos POST con contraseñas Wi-Fi/admin; los valores tampoco se imprimen desde
  el firmware de aplicación.
- Blocklist remota: proteger el acceso a `/upload`, `/fetchnow` y `/setupdate` no
  hace segura su implementación. P5.2 no corrige el reemplazo destructivo,
  límites/atomicidad, HTTP remoto, `setInsecure()`, autenticidad, redirects ni
  SSRF; los correspondientes gates de PILOT siguen abiertos.
- Alternativas: se descartan contraseña hardcoded o plaintext en NVS, Basic Auth
  en cada request, SameSite como única defensa CSRF, tokens persistidos, una
  dependencia web/auth de terceros y un HTTPS aparente sin identidad/cadena de
  confianza. Deshabilitar todo el panel sería más pequeño, pero no cumple el HIL
  administrativo solicitado; sigue siendo una alternativa válida para PILOT si
  no se puede proteger el canal.
- Consecuencias: TM-01, TM-02, TM-16, TM-17, TM-18 y TM-19 son candidatas directas
  a `MITIGATED`, no `CLOSED`. El access control reduce parcialmente TM-03 a
  TM-06 y TM-08; el throttle solo cubre la parte login de TM-20; el gesto físico
  solo reduce parte de TM-10/TM-11/TM-30. Todas conservan sus fallos semánticos o
  controles pendientes. HTTP claro permite a un observador on-path capturar
  contraseña/cookie y el portal físico sigue abierto: PILOT permanece **NO-GO**.
- Verificación requerida: tests host de KDF/almacenamiento, aleatoriedad y vida de
  sesión, flags de cookie, logout, throttle, matriz ruta/método/auth/CSRF,
  allowlist de `Host`, escape contextual, DOM, CSP, regresión OTA/RF y archivos
  protegidos; después, build y medición exacta. Navegador/HIL debe validar BOOT,
  alta/reset, login, expiración/reboot, hosts y puertos, CSRF ausente/erróneo,
  corpus XSS y regresión DNS.
- Verificación local final: 99 tests aprobados (32 de P5.2), Ruff y diff checks
  correctos. PlatformIO enlaza 1.249.513 B (90,8 %) y 51.292 B de RAM (15,7 %).
  El binario físico mide 1.291.104 B, deja 85.152 B (83,16 KiB) y tiene SHA-256
  `F87A9498C1E182A72E881C9C4BFBEE1AF2F2ACF9694A0B4352F0366278EB5463`. P5.2 y su
  enmienda P5.2a quedaron committed y pushed en `bbeacda`; una persona confirmó
  ambos jobs de CI verdes y el HIL completo solicitado. Esa evidencia no elimina
  el riesgo del canal HTTP ni autoriza un piloto.

### Enmienda P5.2a — autorización BOOT en runtime

- Fecha: 2026-08-08.
- Estado: accepted; CI y HIL confirmados en `bbeacda`.
- Motivo: GPIO9/BOOT es un pin de strapping del ESP32-C3. La doble lectura LOW
  durante `setup()`, separada 60 ms, exigía una secuencia frágil tras liberar
  reset y contradecía las instrucciones que recomendaban mantener BOOT durante
  el arranque.
- Decisión: `setup()` solo configura el pull-up. Dos máquinas de estado no
  bloqueantes, armadas después de observar BOOT liberado, exigen LOW continuo
  durante tres segundos en el portal o cinco segundos en STA. Soltar el botón o
  un rebote a HIGH reinicia el conteo. El portal rota su CSRF y permanece activo;
  el guardado y STA esperan una liberación estable antes de reiniciar para no
  muestrear GPIO9 LOW como strap. STA invalida sesión/CSRF y borra
  Wi-Fi/verificador antes de quedar pendiente del release.
- Fallo AP: si `WiFi.softAP()` no arranca, no se inicia DNS/web ni se anuncia un
  portal inexistente. El firmware queda detenido de forma fail-closed, cediendo
  CPU y sin crear un bucle de reinicios.
- Límites: el polling puede retrasarse durante operaciones sincrónicas ya
  existentes; los clears NVS todavía no propagan su resultado; el portal abierto
  y la autorización sin expiración siguen siendo solo DEVELOPMENT. La secuencia
  BOOT+RESET documentada para el downloader ROM permanece separada y nunca es el
  gesto de provisioning.
- Verificación local: 105 tests aprobados, Ruff y diff checks correctos. El build
  enlaza 1.250.561 B de flash y usa 51.332 B de RAM. `firmware.bin` mide
  1.292.272 B, deja 83.984 B físicos y tiene SHA-256
  `534B18024AF53267565C97BAB39A704614172E85C464C146066C6B28483BEEAE`.
  Frente a P5.2 son +1.048 B enlazados, +40 B RAM y +1.168 B físicos; el margen
  sigue por encima del gate de 64 KiB. Una persona confirmó los dos jobs de CI y
  el HIL completo de esta revisión. Esto valida `bbeacda`, no P5.3a ni un piloto.

## ADR-006 — P5.3a solo local y reemplazo recuperable de blocklist

- Fecha: 2026-08-09.
- Estado: accepted; validación HIL de cortes pendiente.
- Contexto: el fetch remoto heredado aceptaba URL configurable, HTTP y TLS con
  `setInsecure()`, seguía redirects y volvía a resolver el destino sin una
  defensa SSRF completa. La plataforma fijada permite separar IP de conexión y
  hostname TLS, pero el bundle CA completo no respeta el margen de flash y la
  configuración MbedTLS precompilada no comprueba automáticamente la vigencia
  temporal X.509. Mantener un fetch parcialmente endurecido no cumple el perfil
  de seguridad de esta entrega.
- Decisión de alcance: eliminar `/fetchnow`, `/setupdate`, URL, intervalo,
  scheduler y UI de actualización remota. No sustituirlos por HTTP, TLS inseguro
  ni una allowlist incompleta. Conservar únicamente `/upload`, protegido por la
  sesión y CSRF de P5.2, y avisar en español que solo deben usarse archivos de
  blocklist validados.
- Archivos: `/blocklist.bin` es la copia activa, `/blocklist.new` el candidato y
  `/blocklist.old` el rollback temporal. El candidato se escribe y cierra antes
  de validarlo. Solo una validación completa permite comenzar el reemplazo; un
  candidato inválido se elimina sin destruir un activo válido. Generador y
  firmware comparten un máximo de 104.857 registros de cinco bytes: 524.285
  bytes, dejando espacio para las dos copias necesarias en LittleFS. Un activo o
  rollback legacy estructuralmente válido puede seguir leyéndose hasta el
  máximo histórico de 1.250.000 bytes; no se borra para intentar hacer hueco. Si
  no cabe la candidata junto a él, el upload falla y conserva el activo.
- Commit transaccional: mover el activo válido a rollback, promover el candidato
  y revalidar el activo resultante. Un fallo conserva o intenta restaurar la
  última copia válida. El firmware no interpreta una lista que no haya superado
  las validaciones de formato y límites.
- Protocolo HTTP: multipart es el único cuerpo admitido por `/upload`; un
  dispatcher separa el callback multipart del callback raw compartido por
  `WebServer` y devuelve 415 para raw/urlencoded sin abrir staging.
- Orden de arranque: montar LittleFS sin autoformato y ejecutar la recuperación
  antes de leer el resto del estado o iniciar STA, SoftAP, mDNS, UDP/53 o el
  servidor HTTP. El montaje o recovery fallidos detienen el arranque sin reboot
  loop ni servicio de red parcialmente funcional.
- Recuperación al boot: (A) un activo válido tiene precedencia y limpia
  candidato/rollback residuales; (B) sin activo válido, un rollback válido se
  restaura y revalida; (C) sin activo ni rollback válidos, un candidato válido se
  promueve y revalida; (D) un candidato inválido nunca desplaza un activo válido;
  (E) sin ninguna copia válida se falla cerrado y no se presenta una lista vacía
  como actualización correcta.
- Corte de alimentación: (1) durante upload, el activo gana y se elimina el
  candidato parcial; (2) después de cerrar el candidato, el activo gana y elimina
  ese staging todavía no confirmado; (3) después de validarlo pero antes de
  `active -> old`, el activo también gana; (4) después de `active -> old`, se
  restaura el rollback válido, salvo que sea inválido y el candidato sea válido;
  (5) después de `new -> active`, el nuevo activo válido gana; (6) antes de
  limpiar old, el nuevo activo gana y elimina el rollback residual. Estas
  propiedades necesitan HIL específico porque los tests host no prueban la
  durabilidad real de rename/remove en LittleFS.
- Multipart y concurrencia: el tamaño de fichero se limita por cada chunk a
  524.285 B. Como filtro temprano, el `Content-Length` del request completo admite
  4.096 B adicionales de framing (528.381 B en total); un framing o filename
  excepcionalmente grande puede recibir un 413 conservador. `WebServer` procesa
  el multipart de forma síncrona. Los guards de parte adicional/transacción
  huérfana son gates host-estáticos y no prueban desconexión, timeout, cliente
  lento, recuperación del loop/DNS ni rate limiting en placa.
- Migración: `/update.cfg` deja de ser configuración activa y desaparece del
  código de producción. Si una unidad conserva ese archivo legacy, queda inerte:
  no se abre, interpreta ni usa para habilitar de nuevo el fetch remoto. Puede
  seguir ocupando LittleFS y reteniendo una URL o token histórico hasta una
  restauración física; su retirada no forma parte de esta migración automática.
- Consecuencias: desaparecen la superficie SSRF/TLS/redirect de actualización
  remota y sus costes de flash. El upload manual sigue siendo una operación
  administrativa sobre HTTP local y no aporta firma, procedencia ni
  confidencialidad. Si no queda ninguna copia válida, la recuperación requiere
  restaurar físicamente por USB una imagen LittleFS conocida y validada; no se
  ofrece recuperación remota. PILOT continúa **NO-GO**. Una futura
  reintroducción de fetch requiere otra ADR con política de destinos, resolución
  fijada, CA, tiempo confiable, redirects manuales, autenticidad y presupuesto
  medido.
- Verificación local: 163 tests aprobados y Ruff sin errores. El build terminó
  `SUCCESS` con 50.684 B de RAM, 1.122.703 B de flash enlazada y 253.553 B de
  margen enlazado. `firmware.bin` mide 1.160.704 B, deja 215.552 B físicos y su
  SHA-256 es
  `D1A24F2D579D6B1617850B07E6FA2A403CBF90E08DDD5DD033475D33B7C34F2C`. Frente a
  P5.2a reduce 648 B de RAM, 127.858 B enlazados y 131.568 B físicos. Los tres
  warnings del build indican que, sin Internet, se omitió la comprobación remota
  de dependencias. `ci_checks repository`, los diff checks y el gate de archivos
  protegidos pasan localmente. Permanecen pendientes CI real confirmada,
  multipart en WebServer real, upload/browser HIL y cortes controlados en las
  seis fronteras; P5.3a no está `CLOSED`.
