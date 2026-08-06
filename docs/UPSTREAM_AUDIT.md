# Auditoría upstream de NetShield Mini

- Fecha: 2026-07-28
- Alcance: starter exterior y repositorio Git anidado `netshield-mini/`
- Revisión auditada: `7f22dbdf25538c5bc1c13cdc9f4c8ebf251cac5a` (`develop`)
- Base local del fork: `453b5be` (`main` y `origin/main`)
- Hardware objetivo: ESP32-C3 SuperMini, flash de 4 MiB, sin PSRAM
- Resultado: **NO-GO para desplegar o flashear el firmware actual**

Esta auditoría es de arquitectura, reproducibilidad y seguridad. No se modificó
firmware, no se flasheó ninguna placa, no se cambió DNS, DHCP, Wi-Fi ni router, y
no se instalaron paquetes globales. La única modificación documental es este
archivo. Los builds dejaron solo artefactos ignorados por Git, detallados al
final.

El código es un prototipo compacto con una idea adecuada para el hardware:
hashes de 40 bits ordenados en LittleFS y búsqueda binaria sin cargar la lista
en RAM. Sin embargo, no cumple todavía los mínimos de seguridad y
reproducibilidad de NetShield Mini. Los bloqueantes principales son:

1. administración y dos mecanismos de OTA sin autenticación;
2. blocklist remota con HTTP permitido y TLS desactivado;
3. reemplazo destructivo de la blocklist, sin límite, firma ni validación real;
4. entradas web que permiten XSS y agotamiento de memoria;
5. build limpio no reproducible y configuración serie incompatible con Windows;
6. ausencia total de tests ejecutables y CI.

La licencia MIT y la atribución upstream siguen presentes. No se encontró una
credencial Wi-Fi real en los archivos rastreados ni en el escaneo textual de los
binarios publicados. El producto debe describirse como reducción de publicidad,
rastreadores y dominios maliciosos a nivel DNS; no como bloqueo total.

## 1. Mapa de archivos

### 1.1 Dos raíces distintas

La carpeta abierta no es un repositorio Git. Es un starter que contiene el
repositorio real como subcarpeta:

```text
./
├── AGENTS.md
├── README_START_HERE.md
├── PRODUCT_REQUIREMENTS.md
├── ROADMAP.md
├── SECURITY.md
├── CODEX_PROMPTS.md
├── FIRST_COMMANDS_WINDOWS.txt
├── .gitignore.additions
├── docs/
│   ├── DECISIONS.md
│   ├── TEST_PLAN.md
│   ├── WINDOWS_NOTES.md
│   └── UPSTREAM_AUDIT.md          <- este informe
├── scripts/
│   ├── bootstrap_windows.ps1
│   ├── check_esp32_port.ps1
│   └── clone_upstream.ps1
└── netshield-mini/                <- repositorio Git real
    ├── .git/
    ├── .gitignore
    ├── AGENTS.md y documentación copiada del starter
    ├── LICENSE
    ├── README.md
    ├── platformio.ini
    ├── partitions.csv
    ├── src/
    │   ├── main.cpp
    │   ├── page.h
    │   └── secrets.example.h
    ├── tools/
    │   └── build_blocklist.py
    ├── data/
    │   └── .gitkeep
    ├── docs/                       <- instalador web y binarios publicados
    │   ├── index.html
    │   ├── manifest.json
    │   ├── bootloader.bin
    │   ├── partitions.bin
    │   ├── boot_app0.bin
    │   ├── firmware.bin
    │   └── littlefs.bin
    ├── netshield-mini/             <- segunda copia del mismo instalador
    │   └── mismos siete archivos
    └── hardware/
        └── esp32-c3-supermini-enclosure.stl
```

Antes de ejecutar builds había 14 archivos en el starter y 37 archivos
rastreados o de producto en el repositorio anidado, excluyendo `.git` y `.pio`.
Los diez documentos que aparecen en ambas raíces eran idénticos byte a byte.
Esta duplicación permite que instrucciones y requisitos se desincronicen. Este
informe se creó en `docs/UPSTREAM_AUDIT.md` de la carpeta solicitada, que no está
bajo Git; el repositorio versionado está un nivel más abajo.

### 1.2 Responsabilidad de cada grupo

| Ruta | Responsabilidad | Observación |
|---|---|---|
| `netshield-mini/src/main.cpp` | DNS, persistencia, panel, onboarding y OTA | Todo está acoplado en un único archivo |
| `netshield-mini/src/page.h` | HTML/CSS/JS del panel en `PROGMEM` | Datos no confiables llegan a `innerHTML` |
| `netshield-mini/tools/build_blocklist.py` | Normalización, hash y binario | Solo biblioteca estándar; sin tests |
| `netshield-mini/platformio.ini` | Entorno PlatformIO `c3` | Plataforma flotante y puertos Linux fijos |
| `netshield-mini/partitions.csv` | Dual OTA y LittleFS | Ocupa exactamente los 4 MiB |
| `netshield-mini/data/` | Entrada de `buildfs` | Upstream solo versiona `.gitkeep` |
| `netshield-mini/docs/` | Instalador ESP Web Tools | Binarios sin procedencia ni digests en manifiesto |
| `netshield-mini/netshield-mini/` | Copia del instalador | Idéntica; añadida en el commit local `7f22dbd` |
| `netshield-mini/hardware/` | Carcasa imprimible | STL de 112.184 bytes |
| `scripts/` exterior | Bootstrap, clon y detección COM | PowerShell válido; versiones no fijadas |

### 1.3 Git, licencia y atribución

- `netshield-mini/LICENSE` conserva MIT, copyright 2026 `zed`.
- `README.md` conserva créditos y referencia a la licencia.
- `docs/index.html` enlaza al proyecto `M-Abozaid/esp32-c3-adblock` y declara MIT.
- `LICENSE` no cambió entre `origin/main` y `develop`.
- El repositorio anidado estaba limpio al iniciar; `develop` está un commit por
  delante de `origin/main` y no tiene tracking branch.
- No hay tags ni refs locales descargadas para el remoto `upstream`; esta
  auditoría describe el checkout local, no el estado actual de GitHub.
- El starter exterior no contiene una licencia propia y no está versionado.

## 2. Flujo DNS

El flujo implementado en `netshield-mini/src/main.cpp` es:

```text
cliente UDP :53
    |
    v
WiFiUDP dnsServer -> lee como máximo 600 bytes
    |
    v
parseQuery()
  - QNAME sin compresión
  - minúsculas
  - elimina "www."
  - extrae QTYPE
    |
    +--> cliente marcado como banned ------------------------+
    |                                                        |
    +--> FNV-1a 40-bit del dominio y sufijos padre           |
            |                                                |
            +--> búsqueda binaria en LittleFS                |
            +--> búsqueda lineal en customHash[]             |
                     |                                       |
                     +---- coincidencia ----------------------+
                     |                                       |
                     v                                       v
                  permitido                              bloqueado
                     |                                       |
                     v                                       +--> A: 0.0.0.0, TTL 300
      reenvío UDP síncrono a 9.9.9.9:53                       +--> otros tipos: NOERROR/NODATA
      espera máxima 1 s                                      |
                     |                                       |
                     +---------------- respuesta al cliente <-+
```

### 2.1 Comportamiento comprobado

- El upstream está fijado a Quad9 `9.9.9.9:53`; no es configurable
  (`main.cpp:24-25`), pese al requisito de producto.
- El buffer global DNS es de 600 bytes (`main.cpp:35`).
- `parseQuery()` exige 13 bytes, rechaza punteros de compresión en QNAME,
  convierte la consulta a minúsculas y extrae QTYPE (`main.cpp:141-149`).
- `isBlocked()` prueba el nombre completo y sufijos padre, pero no el TLD
  (`main.cpp:75-83`).
- El formato de respuesta bloqueada elimina registros adicionales, importante
  para consultas con EDNS (`main.cpp:150-155`).
- Una consulta A bloqueada recibe `0.0.0.0`; AAAA y otros tipos reciben una
  respuesta válida sin answers.
- Las consultas permitidas se reenvían sin caché, reintento ni upstream
  alternativo (`main.cpp:156-160`).
- Se procesan hasta 16 paquetes antes de devolver control a web/OTA
  (`main.cpp:164-181`).

### 2.2 Defectos y límites

- No se validan `QDCOUNT`, `QCLASS`, `QR`, opcode ni la estructura completa del
  paquete.
- Una consulta de un cliente no marcado como banned que no se puede analizar se
  reenvía como si fuese permitida; no se distingue un paquete inválido de un
  miss.
- No se comprueba que la respuesta upstream coincida en ID, origen y pregunta
  con la consulta pendiente.
- Consultas o respuestas mayores de 600 bytes pueden truncarse sin marcar `TC`.
- No hay TCP fallback, caché, tratamiento explícito de DNSSEC ni rate limiting.
- La espera upstream es síncrona. Con upstream caído, una ráfaga de 16 consultas
  puede retener el loop unos 16 segundos, bloqueando panel y OTA.
- `totalAllowed` aumenta aunque el upstream no responda.
- La condición de `main.cpp:175` exige `numHashes > 0` antes de llamar a
  `isBlocked()`. Si la lista principal falta o está siendo reemplazada, también
  quedan desactivados los dominios personalizados.
- La tabla conserva como máximo 96 clientes y no expira entradas. Al llenarse,
  un IP guardado en la lista de prohibidos pero aún no materializado en
  `clients[]` puede eludir el ban porque `getClient()` devuelve `nullptr`.
- No existen allowlist, DNS upstream configurable, watchdog explícito ni
  reconexión Wi-Fi, todos ellos previstos en requisitos.

## 3. Formato y generación de la blocklist

### 3.1 Formato binario

| Propiedad | Valor |
|---|---|
| Hash | FNV-1a de 64 bits truncado a 40 bits |
| Tamaño por entrada | 5 bytes |
| Endianness | little-endian |
| Orden | valor numérico ascendente |
| Duplicados | se eliminan hashes repetidos |
| Acceso firmware | búsqueda binaria directamente en LittleFS |
| Cabecera/magic/versión | no existe |
| Contador/tamaño declarado | no existe |
| Checksum/firma | no existe |

El algoritmo coincide entre `tools/build_blocklist.py:21-40,75-80` y
`src/main.cpp:27-28,59-72`.

### 3.2 Generación

Sin fuentes explícitas, el script:

1. descarga StevenBlack `master/hosts` y HaGeZi `main/domains/light.txt`;
2. elimina comentarios y reconoce algunos formatos hosts o una entrada por línea;
3. convierte a minúsculas, elimina wildcard/puntos extremos y el prefijo `www.`;
4. acepta cualquier valor que contenga un punto;
5. deduplica dominios, calcula hashes, cuenta colisiones observadas;
6. ordena hashes y escribe directamente el archivo destino.

El docstring dice HaGeZi **Pro**, pero el código usa **Light**. Las dos URLs
apuntan a ramas mutables y no hay revisión, fecha, ETag, digest ni snapshot, por
lo que dos builds en fechas distintas no son reproducibles.

La validación no comprueba:

- longitud total ni longitud de labels DNS;
- caracteres permitidos, ASCII/IDNA o IP literales;
- sintaxis completa de hosts/adblock;
- tamaño máximo para la partición;
- que haya al menos una fuente válida;
- integridad o autenticidad de la descarga.

Si todas las fuentes fallan, el script captura los errores, crea un archivo
vacío y termina con código 0. Esto se reprodujo en el primer intento aislado.
También escribe directamente sobre el destino, sin temporal y rename atómico.

### 3.3 Resultado de esta auditoría

La ejecución autorizada con descarga produjo:

| Métrica | Resultado |
|---|---:|
| Dominios fuente únicos | 145.007 |
| Entradas hash | 145.007 |
| Colisiones observadas | 0 |
| Tamaño | 725.035 bytes |
| Búsquedas estimadas | 18 lecturas |
| Orden estrictamente creciente | sí |
| SHA-256 | `915826d347fe3fcbb52a7da5df9e36f541de79ccaf7b1dcd98dadf94c37781ec` |

Este resultado solo prueba las fuentes observadas el 2026-07-28; no identifica
el contenido del `littlefs.bin` publicado. La inspección binaria de esa imagen
sugiere un `blocklist.bin` histórico distinto, pero no pudo montarse con
`mklittlefs` porque el paquete de plataforma no estaba instalado. No hay log que
relacione los binarios publicados con fuentes y revisiones concretas.

### 3.4 Validación en el dispositivo

La subida y descarga remota solo aceptan un blob si su tamaño es positivo y
múltiplo de cinco (`main.cpp:223-230`). No se verifican:

- orden ascendente y unicidad;
- máximo de partición;
- magic, versión o número de entradas;
- checksum/firma;
- escritura completa;
- procedencia.

En el arranque se usa `size / 5` sin comprobar el resto
(`main.cpp:390-392`). Una lectura/seek fallida en `inFlash()` tampoco se trata
explícitamente.

## 4. Particiones y límites

La tabla `partitions.csv` y el `partitions.bin` publicado coinciden:

| Partición | Offset | Tamaño | Fin | Uso |
|---|---:|---:|---:|---|
| `nvs` | `0x9000` | `0x5000` = 20.480 B | `0xE000` | Preferences/Wi-Fi |
| `otadata` | `0xE000` | `0x2000` = 8.192 B | `0x10000` | selección OTA |
| `app0` | `0x10000` | `0x150000` = 1.376.256 B | `0x160000` | firmware |
| `app1` | `0x160000` | `0x150000` = 1.376.256 B | `0x2B0000` | firmware OTA |
| `spiffs` | `0x2B0000` | `0x150000` = 1.376.256 B | `0x400000` | LittleFS |

La etiqueta `spiffs` es heredada, aunque PlatformIO construye y el firmware
monta LittleFS. El layout termina exactamente en `0x400000`: no queda flash sin
asignar.

### 4.1 Firmware OTA

- Cada slot mide 1.376.256 bytes (1,3125 MiB).
- `docs/firmware.bin` mide 1.299.024 bytes.
- Ocupación respecto al slot: 94,39 %.
- Margen: 77.232 bytes, 75,42 KiB o 5,61 %.

El comentario de `partitions.csv:2` afirma unos 134 KB de margen y está
obsoleto. No debe añadirse funcionalidad significativa sin medir el ELF/map y
aplicar un gate automático de tamaño.

### 4.2 LittleFS y blocklist

- Máximo matemático sin filesystem: `floor(1.376.256 / 5) = 275.251` hashes.
- 250.000 hashes ocupan 1.250.000 bytes y dejan 126.256 bytes brutos.
- La lista generada en esta auditoría deja 651.221 bytes brutos.
- El máximo real es menor por metadatos LittleFS y por `custom.txt`,
  `banned.txt` y `update.cfg`.

La documentación menciona una tabla single-app para 370k/537k dominios, pero no
existe esa tabla en el repositorio. Cambiar particiones requerirá cálculo
separado y aprobación humana; no se propone hacerlo en este parche.

### 4.3 Instalador publicado

Los offsets de ambos `manifest.json` son coherentes:

| Parte | Offset |
|---|---:|
| `bootloader.bin` | `0x0000` |
| `partitions.bin` | `0x8000` |
| `boot_app0.bin` | `0xE000` |
| `firmware.bin` | `0x10000` |
| `littlefs.bin` | `0x2B0000` |

`new_install_prompt_erase` está activado: usar el instalador borra el contenido
previo de la placa. No se ejecutó.

Los dos juegos publicados son idénticos byte a byte. Cada juego de cinco
binarios ocupa 2.706.064 bytes; con HTML y manifiesto ocupa 2.710.608 bytes.

| Binario | Bytes | SHA-256 |
|---|---:|---|
| `boot_app0.bin` | 8.192 | `F94C5D786A7A8FAB06AC5D10E33BF37711A6697636DC037559EA19CC410A17F0` |
| `bootloader.bin` | 19.520 | `E6397E68487ADA6E81A273C4B24966418EF6CBF389BAE7801363C97DDCBDAEB9` |
| `firmware.bin` | 1.299.024 | `25FF30D749091A77EA44C6A7C8A36D76BEE83E11A9DE23A4385416DFF10F1E90` |
| `littlefs.bin` | 1.376.256 | `88B84406092CD994662F6CCF008076AC88E99C56A5481B22AE0F0C7F2E6A2D4E` |
| `partitions.bin` | 3.072 | `D847F381BACDD34EE76954807DDA999F1E92D83DF521F8AFC9561E445562B17E` |

El manifiesto no publica estos hashes ni enlaza versión, commit, toolchain y
fuentes. El versionado `1.0.0` no basta para demostrar procedencia.

## 5. RAM y flash

### 5.1 Lo que puede afirmarse

La imagen publicada contiene aproximadamente:

| Segmento extraído | Bytes |
|---|---:|
| DROM mapeada | 232.860 |
| IROM mapeada | 987.740 |
| DRAM inicializada | 14.548 |
| IRAM cargada | 63.724 |
| RTC | 32 |

Estas cifras no incluyen BSS, heap, stacks ni reservas internas de Wi-Fi/TLS.
Por tanto, no validan la afirmación del README de “~50 KB de RAM”.

Las tablas visibles en código consumen aproximadamente:

- `buf[600]`: 600 B;
- `customHash[200]`: 1.600 B;
- `bannedIP[32]`: 128 B;
- `clients[96]`: entre 3.840 y 4.224 B, según tamaño de `String`;
- `customDom[200]`: entre 2.400 y 3.200 B.

Solo estas estructuras rondan 8,6-9,8 KiB. Faltan objetos de red, filesystem,
web, TLS, stacks, BSS y asignaciones dinámicas.

### 5.2 Riesgos de heap

- Hay 296 objetos `String` en tablas estáticas; `Dev::label` no se usa.
- Los dominios personalizados no tienen longitud máxima.
- `/stats.json` se construye concatenando `String` para hasta 96 clientes y 200
  dominios.
- El portal construye HTML dinámico con hasta 15 SSID.
- La descarga remota usa TLS/HTTP y un buffer de stack de 1.024 B.
- Las concatenaciones y actualizaciones repetidas pueden fragmentar el heap.

El panel muestra heap libre instantáneo, pero no heap mínimo, high-water mark,
fragmentación ni datos bajo carga. Hace falta un build con ELF/map y pruebas en
hardware de heap mínimo durante DNS + HTTP + TLS. No se debe usar la cifra de
50 KB como presupuesto demostrado.

### 5.3 Riesgo de flash

El firmware publicado ya usa el 94,39 % de cada slot. LittleFS comparte su
partición entre blocklist y tres archivos de estado. Además, persistir
custom/bans/configuración y repetir uploads provoca escrituras y posible
desgaste; no hay rate limiting ni política de frecuencia.

## 6. Onboarding, panel y OTA

### 6.1 Onboarding

Flujo actual:

1. monta LittleFS con `LittleFS.begin(true)`;
2. lee SSID/password de NVS;
3. si no existen, usa constantes de `secrets.h`;
4. intenta conectar durante 20 segundos;
5. ante cualquier fallo, escanea redes y abre `C3-AdBlock-XXXX` sin contraseña;
6. sirve un portal HTTP y DNS cautivo indefinidamente;
7. guarda SSID/password en NVS y reinicia.

Aspectos positivos:

- el AP deja de existir después de guardar y reiniciar;
- BOOT/GPIO9 permite borrar Wi-Fi al arrancar;
- la contraseña no se imprime por serie;
- el portal y el panel normal no quedan activos a la vez en el flujo actual.

Problemas:

- `src/secrets.h` se incluye incondicionalmente pero no existe en un clon limpio;
  README lo presenta incorrectamente como opcional;
- un fallo transitorio del router abre el AP de recuperación;
- el AP no tiene contraseña, presencia física obligatoria ni timeout;
- SSID/password viajan por HTTP sobre ese AP abierto y quedan en NVS sin
  configuración documentada de cifrado;
- no hay límites explícitos de SSID/password ni comprobación del resultado de
  persistencia;
- `LittleFS.begin(true)` formatea automáticamente ante un fallo de montaje y
  puede borrar blocklist/configuración;
- tras perder Wi-Fi durante operación normal no hay reconexión ni recuperación.

### 6.2 Panel

El panel se anuncia por mDNS y escucha HTTP en puerto 80. Expone:

| Ruta | Función | Riesgo principal |
|---|---|---|
| `/stats.json` | IP, MAC, contadores, heap, RSSI y configuración | sin autenticación; fuga de datos LAN |
| `/ban` | cambia ban de un cliente | mutación invocada por GET, sin CSRF |
| `/addblock`, `/unblock` | cambia dominios locales | entrada débil, XSS persistente |
| `/forgetwifi` | borra Wi-Fi y reinicia | DoS/configuración abierta |
| `/upload` | sustituye blocklist | sin autenticación ni límite |
| `/update` | instala firmware | OTA crítica sin autenticación/firma |
| `/fetchnow`, `/setupdate` | descarga/configura URL | SSRF, TLS inseguro, secretos en URL |

No hay login, autorización, CSRF token, comprobación de `Origin`/`Host`,
restricción de métodos para varias rutas ni rate limiting. Tampoco hay una
política de aplicación que rechace clientes fuera de la LAN; la exposición WAN
depende por completo del router.

El panel no muestra una versión de firmware real, pese a RF-08. Panel, portal e
instalador están en inglés, contrario a los requisitos de interfaz en español.

### 6.3 OTA de blocklist

`beginBlocklistSwap()` cierra y elimina la lista viva antes de recibir la nueva.
Durante el proceso `numHashes=0`, por lo que el equipo queda fail-open. Un cliente
LAN puede iniciar una subida y abortarla para desactivar el filtrado.

La validación final solo exige un tamaño positivo múltiplo de cinco. Un archivo
parcial cuyo tamaño cumpla esa condición puede aceptarse. No se comprueban
escrituras, orden, límite, checksum ni firma, y no se conserva una última lista
conocida buena.

### 6.4 Descarga remota

`fetchBlocklist()`:

- acepta URL arbitraria, incluido HTTP;
- usa `WiFiClientSecure::setInsecure()` para HTTPS;
- sigue redirecciones;
- no limita bytes totales;
- bloquea el loop durante la transferencia;
- borra la lista viva después de recibir HTTP 200;
- persiste, expone en `/stats.json` e imprime la URL completa.

Esto permite manipulación de política, SSRF limitado contra la LAN, agotamiento
de flash/tiempo y fuga de tokens si se introducen en la URL.

### 6.5 OTA de firmware

Hay dos superficies:

1. `/update` usa `Update.begin(UPDATE_SIZE_UNKNOWN)` y `Update.end(true)`;
2. `ArduinoOTA.begin()` habilita subida de red para PlatformIO.

Ninguna configura autenticación administrativa, password/hash de ArduinoOTA,
firma de editor, anti-rollback ni presencia física. `Update` puede validar
estructura/checksum técnico, pero no la identidad de quien publicó el firmware.
Por tanto, las frases de UI/README que dicen que el dispositivo “verifica” la
imagen son engañosas. Un atacante con acceso LAN podría instalar firmware
arbitrario.

## 7. Dependencias

### 7.1 Firmware

No hay `lib_deps`. El código usa componentes incluidos en Arduino-ESP32/lwIP:

- Arduino;
- WiFi y WiFiUDP;
- LittleFS;
- ESPmDNS;
- WebServer;
- Update;
- HTTPClient y WiFiClientSecure;
- ArduinoOTA;
- DNSServer;
- Preferences;
- APIs internas `lwip/etharp.h` y `lwip/netif.h`.

`platform = espressif32` y `framework = arduino` no están fijados. El binario
publicado contiene cadenas compatibles con Arduino 3.3.7, ESP-IDF
`v5.5.2-729-g87912cd291` y rutas Linux `/home/zed/.platformio`, pero
`platformio.ini` no permite reproducir esa combinación.

### 7.2 Python y herramientas

El generador usa solo `sys`, `os`, `math` y `urllib.request`. No existen
`pyproject.toml`, `requirements.txt`, lockfile ni configuración de ruff/pytest.

El entorno observado contiene:

| Herramienta | Versión/estado |
|---|---|
| Python de la venv | 3.14.3 |
| PlatformIO Core | 6.1.19 |
| pytest | 9.1.1 |
| ruff | 0.16.0 |
| Git | 2.53.0.windows.1 |
| `pio` en `PATH` | no |
| plataforma `espressif32` cacheada | no |

`bootstrap_windows.ps1` instala en una venv de usuario, no globalmente, pero
actualiza versiones flotantes de pip, PlatformIO, pytest y ruff.

### 7.3 Dependencias remotas y supply chain

- Las fuentes de blocklist usan ramas `master`/`main` mutables.
- El instalador carga
  `https://unpkg.com/esp-web-tools@10/dist/web/install-button.js?module` en
  tiempo de ejecución: rango mayor flotante, sin SRI ni copia local.
- Ese JavaScript externo controla el proceso de flasheo.
- Los manifiestos no incluyen digest, firma, commit ni procedencia.
- `FIRST_COMMANDS_WINDOWS.txt` recomienda descargar y ejecutar un script remoto
  con `irm ... | iex`; debe verificarse antes de usar.

## 8. Compatibilidad Windows 10 y puertos COM

Entorno comprobado:

- Windows 10 Pro x64, versión/build `10.0.19045`;
- Windows PowerShell `5.1.19041.6456`;
- la comprobación de solo lectura no encontró puertos COM;
- no se abrió ningún puerto.

Bloqueantes:

- `platformio.ini:8-9` fija `upload_port` y `monitor_port` a
  `/dev/ttyACM0`. Es incompatible con `COMx`, contradice AGENTS y deshabilita la
  autodetección recomendada.
- `src/main.cpp:20` exige un `secrets.h` ausente aunque el onboarding debería
  permitir un build sin credenciales.
- `pio`, `pytest` y `ruff` no están en `PATH`; sí existen bajo
  `%USERPROFILE%\.venvs\netshield-mini\Scripts`.
- `python3` resuelve mediante el alias WindowsApps; los comandos reproducibles
  deben usar la venv o `py -3`.
- El README upstream usa `cp`, `dig`, rutas `/dev` y comandos Linux sin
  equivalentes PowerShell.
- `PRODUCT_REQUIREMENTS.md` todavía exige un build reproducible en Apple
  Silicon y `ROADMAP.md` prioriza macOS/Linux, mientras la misión y el MVP
  actuales fijan Windows 10 x64 sobre Intel; el alcance debe reconciliarse.
- No hay `.gitattributes`, por lo que el tratamiento de CRLF/LF no queda fijado
  para builds y scripts entre Windows y otros hosts.

Aspectos compatibles:

- los tres scripts `.ps1` parsean sin errores en PowerShell 5.1;
- `check_esp32_port.ps1` usa la ruta absoluta de la venv, `pio device list` y
  `Win32_SerialPort`;
- cuando no se fija un puerto, PlatformIO puede autodetectar `COMx`;
- las notas indican correctamente que se debe identificar el dispositivo USB
  antes de instalar un driver.

La primera ejecución del script quedó bloqueada por la execution policy de la
sesión. Se repitió en un proceso hijo con `-ExecutionPolicy Bypass`, sin cambiar
la política global, y terminó correctamente sin listar puertos.

## 9. Riesgos de seguridad en archivos y funciones

| ID | Nivel | Archivo/función | Riesgo |
|---|---|---|---|
| S-01 | Crítico | rutas admin `main.cpp:407-424` | Panel, borrado Wi-Fi y OTA sin autenticación/autorización |
| S-02 | Crítico | `handleFwUpload()`, `ArduinoOTA.begin()` | Firmware arbitrario desde LAN; sin firma ni password |
| S-03 | Alto | `beginBlocklistSwap()` | Borra la lista conocida buena antes de validar la nueva |
| S-04 | Alto | `fetchBlocklist()` | HTTP, TLS inseguro, redirects, URL arbitraria, sin límite/firma |
| S-05 | Alto | `addCustom()`, `jesc()`, `page.h` | XSS persistente y JSON inválido mediante dominio personalizado |
| S-06 | Alto | `portalOpts`, `handleWifiSave()` | SSID malicioso causa XSS/reflexión durante onboarding |
| S-07 | Alto | `startConfigPortal()` | AP abierto indefinido; captura o sustitución de credenciales |
| S-08 | Alto | uploads HTTP | Sin límite, rate limiting, CSRF ni comprobación de escrituras |
| S-09 | Medio/alto | `parseQuery()`, `forwardUpstream()` | DNS malformado, truncado y respuesta upstream no asociada |
| S-10 | Medio/alto | `String`, JSON y descargas | Agotamiento/fragmentación de heap y bloqueo del loop |
| S-11 | Medio | `LittleFS.begin(true)` | Autoformato y pérdida silenciosa de política/configuración |
| S-12 | Medio | NVS y logging | SSID/URL en claro; tokens de URL expuestos por API/serie |
| S-13 | Medio | `docs/manifest.json` y binarios | Sin digest/procedencia; dos superficies duplicadas |
| S-14 | Medio | `docs/index.html` | JavaScript de flasheo externo sin versión exacta/SRI |

Controles ya presentes:

- `src/secrets.h` y `.env*` están ignorados;
- solo se rastrean placeholders, no credenciales reales;
- no se almacena historial de dominios consultados;
- se guardan contadores agregados y por cliente en RAM;
- el parser aplica límites básicos de buffer/QNAME;
- la licencia y atribución permanecen intactas.

Esos controles no compensan la administración y OTA sin autenticación. El
panel expone IP, MAC y actividad agregada a cualquier cliente que pueda
alcanzarlo.

## 10. Tests presentes y ausentes

### 10.1 Presentes

No hay tests automatizados en el repositorio. Solo existe el plan
`docs/TEST_PLAN.md`.

Durante esta auditoría se ejecutaron comprobaciones no destructivas:

| Comprobación | Resultado |
|---|---|
| Sintaxis de `build_blocklist.py` | OK |
| Generación real de blocklist | OK, 145.007 entradas |
| Tamaño múltiplo de 5 y orden estricto | OK |
| JSON de ambos manifiestos | OK |
| Offsets de manifiesto frente a particiones | coherentes |
| Parseo de los tres scripts PowerShell | 0 errores |
| Hashes de binarios duplicados | idénticos |
| `git fsck --full --strict` | OK, sin salida |
| Búsqueda básica de secretos | sin credenciales reales evidentes |
| `pytest -q -p no:cacheprovider` | exit 5, `no tests ran` |
| `ruff check . --no-cache` | exit 1, cuatro incidencias |
| `pio run` | no completó; ver registro de errores |

Ruff encontró:

1. imports no ordenados (`I001`);
2. preferencia por `removeprefix()` (`FURB188`);
3. captura demasiado amplia de `Exception` (`BLE001`);
4. escritura en loop en vez de `writelines` (`FURB122`).

### 10.2 Ausentes

No existen `test/`, `tests/`, fixtures, pytest, Unity/Catch2, fuzz harness,
Pester, `.github/` ni CI.

Faltan como mínimo:

- tests Python de normalización, hosts/adblock inválido, duplicados, FNV,
  endianness, orden, colisiones, fuentes parciales/vacías y límite de partición;
- tests compartidos Python/C++ que garanticen el mismo hash;
- DNS A, AAAA, EDNS, QDCOUNT, QCLASS, opcode, compresión, truncado, múltiples
  preguntas, paquetes inválidos y fuzz;
- respuestas upstream con ID/origen incorrectos, timeout y caída;
- integración de allowlist/custom list/lista ausente/corrupta;
- uploads vacíos, enormes, parciales, abortados y corte durante swap;
- autenticación, autorización, métodos HTTP, CSRF, DNS rebinding y rate limit;
- XSS en dominio, SSID, JSON, atributo y HTML;
- certificado TLS inválido, redirects, HTTP y URL interna;
- firmware inválido, sin firma, downgrade y recuperación OTA;
- reconexión Wi-Fi, timeout de portal, BOOT y borrado completo;
- gates de firmware, LittleFS, secretos, licencia y checksums;
- heap mínimo, latencia p50/p95, QPS, 24 h y 7 días en hardware.

## 11. Cambios priorizados

### P0 — bloqueantes de ingeniería y seguridad

1. **Hacer reproducible un build limpio en Windows.** La causa inmediata es la
   plataforma no fijada, el `secrets.h` obligatorio/ausente y los puertos Linux
   fijos. Añadir fallback de credenciales vacío, retirar ambos puertos fijos,
   fijar PlatformIO/Arduino-ESP32 y documentar una venv reproducible.
2. **Deshabilitar o proteger toda administración y OTA antes de desplegar.**
   Incorporar autenticación fuerte, autorización, POST para mutaciones, CSRF,
   rate limiting y política LAN explícita. ArduinoOTA debe quedar deshabilitado
   hasta tener password/hash y una decisión de amenaza documentada.
3. **Exigir autenticidad del firmware.** Verificar firma de editor, tamaño antes
   de escribir y política de rollback/recuperación. No presentar checksum técnico
   como verificación de procedencia.
4. **Rehacer la actualización de blocklist como transacción.** Mantener la lista
   activa, descargar a staging con límite duro, validar formato/orden/checksum o
   firma, comprobar cada escritura y hacer rename atómico solo al final.
5. **Eliminar HTTP y `setInsecure()` para política remota.** Usar TLS validado,
   limitar esquema/host/redirects/bytes/tiempo y no aceptar tokens en URLs
   expuestas. Preferir artefactos firmados.
6. **Cerrar XSS y entradas ilimitadas.** Validar dominios/SSID/URLs por longitud
   y sintaxis, usar escapes específicos y `textContent`, nunca `innerHTML` con
   datos no confiables.

### P1 — cobertura y fiabilidad

7. Añadir pytest con fixtures locales, sin descargar listas reales, y un harness
   C++/DNS con casos malformados y fuzz básico.
8. Separar parser DNS, motor de matching, persistencia, web y OTA para poder
   probarlos. Validar cabecera DNS completa, truncado y respuesta upstream.
9. Implementar allowlist, reconexión Wi-Fi, upstream configurable/fallback y
   watchdog conforme a requisitos.
10. Limitar y expirar clientes; aplicar bans aunque la tabla esté llena.
11. Limitar el portal a onboarding o recuperación con presencia física/ventana
    temporal y credencial única. Definir almacenamiento y borrado seguro de
    Wi-Fi; cualquier eFuse/secure boot requiere aprobación humana.
12. Añadir CI con tests, build, análisis estático, búsqueda de secretos, licencia,
    digests y gates de tamaño.

### P2 — producto, recursos y publicación

13. Medir ELF/map, BSS, stacks y heap mínimo bajo carga antes de añadir funciones;
    eliminar `Dev::label` si sigue sin uso y reducir concatenaciones de `String`.
14. Corregir el margen OTA documentado y retirar o proporcionar la tabla
    single-app prometida. No cambiar particiones sin ADR y aprobación.
15. Generar instalador/binarios desde CI reproducible, con versión ligada a
    commit, SHA-256, procedencia y firma. Fijar o autohospedar ESP Web Tools.
16. Eliminar la copia duplicada del instalador y consolidar starter/repositorio
    para que la documentación versionada tenga una única fuente.
17. Traducir onboarding/panel a español, mostrar versión real y corregir promesas
    absolutas sobre bloqueo y “verificación”.
18. Registrar estas decisiones en `docs/DECISIONS.md` y preservar sin cambios la
    licencia MIT y atribución.

## Registro de comandos, builds y errores

Todos los comandos se ejecutaron desde PowerShell. Se muestran rutas abreviadas;
la venv real fue `%USERPROFILE%\.venvs\netshield-mini`.

### Comandos principales

```powershell
rg --files -uu -g '!**/.git/**'
Get-Content -LiteralPath <archivo> -Raw
Get-ChildItem -Recurse -Force -File
Get-FileHash -Algorithm SHA256 -LiteralPath <archivo>

git -C .\netshield-mini status --short
git -C .\netshield-mini branch -vv
git -C .\netshield-mini remote -v
git -C .\netshield-mini log --oneline --decorate
git -C .\netshield-mini ls-files
git -C .\netshield-mini fsck --full --strict

& "$env:USERPROFILE\.venvs\netshield-mini\Scripts\python.exe" `
  tools\build_blocklist.py data\blocklist.bin
& "$env:USERPROFILE\.venvs\netshield-mini\Scripts\pytest.exe" `
  -q -p no:cacheprovider
& "$env:USERPROFILE\.venvs\netshield-mini\Scripts\ruff.exe" `
  check . --no-cache
& "$env:USERPROFILE\.venvs\netshield-mini\Scripts\pio.exe" run

Get-Content .\netshield-mini\docs\manifest.json -Raw | ConvertFrom-Json
[System.Management.Automation.Language.Parser]::ParseFile(...)
Get-CimInstance Win32_OperatingSystem
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\check_esp32_port.ps1
```

### Resultados y errores

| Acción | Resultado registrado |
|---|---|
| Git desde la raíz exterior | `fatal: not a git repository`; el Git real está en `netshield-mini/` |
| Inventario con `[IO.Path]::GetRelativePath()` | falló: el .NET de PowerShell 5.1 no expone ese método; se repitió con rutas por substring |
| Herramientas en `PATH` | `pio`, `platformio`, `pytest` y `ruff` no encontrados; se usaron ejecutables de la venv |
| `pio project config --json-output` aislado | leyó la configuración, pero el hilo de telemetría no pudo crear `.platformio\appstate.json.lock` |
| Primer generador sin acceso de red | ambas URLs fallaron con WinError 10013; el script devolvió 0 y creó una lista vacía |
| Generador con descarga autorizada | exit 0; 145.007 entradas, 725.035 bytes, 0 colisiones observadas |
| Verificación del blob | múltiplo de 5, estrictamente ordenado, SHA-256 registrado arriba |
| `pio run` | exit 1: intentó crear/instalar `C:\Users\Oussama\.platformio\platforms` y recibió `PermissionError [WinError 5]` |
| Repetición elevada de `pio run` | no ejecutada: la caché global estaba vacía y habría instalado paquetes globales, expresamente prohibido |
| Compilación C++ | no alcanzada; además, `src/secrets.h` está ausente en el clon limpio |
| pytest | exit 5; `no tests ran in 0.03s` |
| ruff | exit 1; cuatro incidencias, ninguna corregida |
| Consulta inicial de OS/CIM | acceso denegado dentro del sandbox |
| Script COM inicial | bloqueado por execution policy de la sesión |
| OS/COM repetido en solo lectura | Windows 10 Pro 19045 x64; proceso con bypass temporal; ningún COM detectado |
| Hash/JSON/PowerShell/Git fsck | correctos |

Inspecciones paralelas también registraron timeouts iniciales de 10-15 segundos,
un wildcard literal rechazado por Windows (`os error 123`) y un aviso Git de
`dubious ownership` dentro de una identidad de sandbox. Se repitieron con timeout
mayor, rutas explícitas y `git -c safe.directory=<repo>` por invocación, sin
cambiar configuración global.

### Artefactos locales de build

Quedaron dos artefactos ignorados dentro del repositorio anidado:

- `data/blocklist.bin`: 725.035 bytes;
- `.pio/build/project.checksum`: 40 bytes.

`git status --short` no muestra cambios rastreados en `netshield-mini/`; con
`--ignored` aparecen `!! data/blocklist.bin` y `!! .pio/`. No se borraron para
evitar una operación destructiva no solicitada.

## Conclusión

El upstream demuestra que el enfoque hash-en-flash cabe en el ESP32-C3 y que el
layout dual OTA es técnicamente coherente. No demuestra todavía un build limpio,
seguro o reproducible en Windows, ni una administración apta para una LAN no
confiable. La siguiente unidad de trabajo debería ser un parche pequeño de P0
para recuperar build reproducible sin puertos fijos ni `secrets.h` obligatorio;
después, antes de cualquier flasheo o piloto, deben cerrarse OTA/autenticación y
el reemplazo inseguro de blocklists.

Propuesta de commit, no ejecutada:

```text
docs: add upstream architecture and security audit
```
