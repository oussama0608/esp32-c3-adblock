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
  El workflow no se considera aprobado por GitHub hasta su primera ejecución
  remota después de un push autorizado.

## ADR-004 — Threat model y secuencia de hardening previa al piloto

- Fecha: 2026-08-07
- Estado: accepted
- Implementación: P5.1 local completado; pendiente de commit, CI remota y HIL
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
  La CI remota sigue condicionada a confirmación humana de ambos jobs verdes.
- Verificación P5.1: 64 tests host pasan; el build limpio posterior no enlaza
  ArduinoOTA/Update y el escaneo de binario, ELF y mapa no encuentra sus símbolos,
  handlers ni strings de firmware OTA. La única cadena `/update...` restante es
  `/update.cfg`, propia de blocklist. `firmware.bin` tiene SHA-256
  `DEAEEE6885A8446D678FACC7141F093E3B4061F54C7DFF76CD1693AFB1401367`.
  No se ejecutaron red, puerto serie, flash ni HIL; la CI de esta revisión tampoco
  se considera ejecutada hasta confirmación humana posterior a un push autorizado.
