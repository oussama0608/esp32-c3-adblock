# Recuperación USB en Windows 10

Este procedimiento sustituye a la actualización de firmware por red retirada en
P5.1. Está limitado a una ESP32-C3 SuperMini de 4 MB conectada directamente por
USB a un host Windows 10 x64.

El procedimiento está documentado, pero todavía no se ha validado en hardware.
Flashear, abrir un puerto `COMx` o realizar una prueba HIL requieren aprobación
humana independiente.

No use los instaladores web ni los binarios legacy versionados. La imagen de
recuperación debe construirse localmente desde una revisión conocida, revisada y
con SHA-256 registrado.

## Preparar un artefacto conocido

PlatformIO Core debe permanecer dentro del repositorio. Su instalación inicial
está descrita en [WINDOWS_NOTES.md](WINDOWS_NOTES.md).

Desde PowerShell, en la raíz del repositorio:

```powershell
$repoRoot = (Resolve-Path -LiteralPath ".").Path
$env:PLATFORMIO_CORE_DIR = Join-Path $repoRoot ".platformio"
$pio = Join-Path $env:PLATFORMIO_CORE_DIR "core-venv\Scripts\pio.exe"

if (-not (Test-Path -LiteralPath $pio)) {
    throw "Falta el PlatformIO Core local; consulte docs/WINDOWS_NOTES.md."
}
if (Test-Path -LiteralPath (Join-Path $repoRoot "src\secrets.h")) {
    throw "Detener: src/secrets.h local podría incrustar credenciales en el firmware."
}

$pioVersion = & $pio --version
if ($LASTEXITCODE -ne 0 -or $pioVersion -notmatch "6\.1\.19") {
    throw "Se requiere PlatformIO Core 6.1.19."
}
$pioVersion
git status --short
git diff --quiet HEAD -- partitions.csv LICENSE
if ($LASTEXITCODE -ne 0) {
    throw "partitions.csv o LICENSE difieren de HEAD; no flashear."
}
$trackedSecrets = @(git ls-files -- src/secrets.h)
if ($LASTEXITCODE -ne 0 -or $trackedSecrets.Count -ne 0) {
    throw "src/secrets.h está rastreado; no flashear."
}
git rev-parse HEAD

& $pio run --environment c3 --target clean
& $pio run --environment c3
if ($LASTEXITCODE -ne 0) {
    throw "El build ha fallado; no flashear."
}
```

`git ls-files -- src/secrets.h` debe producir una salida vacía y PlatformIO debe
indicar la versión 6.1.19. No continúe si falla el build, si `partitions.csv` o
`LICENSE` han cambiado o si desconoce el origen de la revisión.

Registre el tamaño y el hash del artefacto exacto:

```powershell
$firmware = Join-Path $repoRoot ".pio\build\c3\firmware.bin"
$firmwareSize = (Get-Item -LiteralPath $firmware).Length
$firmwareHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $firmware).Hash
$slotSize = 1376256

[pscustomobject]@{
    Commit = (git rev-parse HEAD)
    FirmwareBytes = $firmwareSize
    SlotBytes = $slotSize
    FreeBytes = $slotSize - $firmwareSize
    SHA256 = $firmwareHash
}

if ($firmwareSize -gt $slotSize) {
    throw "firmware.bin no cabe en el slot app."
}
```

No edite fuentes entre esta comprobación y el flasheo.

## Identificar el puerto COM

Use un cable USB de datos y cierre cualquier programa que pueda estar usando el
puerto. Liste los dispositivos con el Core local:

```powershell
& $pio device list
```

Anote el puerto de la placa como `COMx`; no presuponga que será `COM3`. Windows
puede asignar otro número al entrar en el bootloader ROM. Si hay dudas, compare
la lista antes y después de conectar la placa y compruebe el Administrador de
dispositivos. No instale un driver hasta identificar la interfaz USB exacta.

## Entrar en el bootloader ROM

En la ESP32-C3 SuperMini, `BOOT` controla GPIO9 y `RESET` puede aparecer marcado
como `RST`.

1. Mantenga pulsado `BOOT`.
2. Pulse y suelte `RESET` sin soltar `BOOT`.
3. Suelte `BOOT` cuando Windows detecte el puerto del bootloader.
4. Vuelva a ejecutar `& $pio device list`, porque el número `COMx` puede haber
   cambiado.

Si la placa no tiene un botón `RESET` accesible, desconéctela, mantenga `BOOT`,
conéctela de nuevo y suelte `BOOT` cuando aparezca el puerto.

GPIO9 también es un pin de arranque. Este gesto selecciona exclusivamente el
downloader ROM y no ejecuta la aplicación ni autoriza provisioning P5.2a. La
recuperación Wi-Fi/admin de la aplicación se inicia solo con el firmware ya en
ejecución: nunca use esta secuencia BOOT+RESET para ese fin.

## Flashear por USB

Sustituya `COMx` por el puerto observado y ejecute solo con aprobación humana:

```powershell
$port = "COMx"
if ($port -notmatch "^COM\d+$") {
    throw "Sustituya COMx por el puerto observado antes de continuar."
}
& $pio run --environment c3 --target upload --upload-port $port
if ($LASTEXITCODE -ne 0) {
    throw "El flasheo USB ha fallado."
}
Get-FileHash -Algorithm SHA256 -LiteralPath ".pio\build\c3\firmware.bin"
```

No fije `upload_port` en `platformio.ini`. Después de una escritura correcta,
pulse `RESET` sin mantener `BOOT`, o desconecte y vuelva a conectar la placa sin
pulsar botones.

Este procedimiento no abre el monitor serie, no configura Wi-Fi y no cambia
DNS, DHCP ni router. Abrir un monitor serie exige aprobación separada.

## Restaurar LittleFS únicamente si es necesario

El target `upload` no restaura LittleFS. No ejecute `uploadfs` solo porque el
firmware no arranca: primero repita el modo ROM y el flasheo de firmware.

`uploadfs` sustituye el contenido completo de LittleFS y puede eliminar la
blocklist, bans, dominios personalizados y configuración guardada allí. No
modifica NVS, pero sigue siendo una operación destructiva y necesita aprobación
específica.

Para una recuperación de laboratorio sin Internet puede generarse una
blocklist mínima usando exclusivamente fixtures locales:

```powershell
$python = Join-Path $env:USERPROFILE ".venvs\netshield-mini\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "Falta el Python de la venv local de NetShield Mini."
}
& $python tools\build_blocklist.py --max-bytes 1024 `
    data\blocklist.bin tests\fixtures\domains.txt tests\fixtures\hosts.txt
if ($LASTEXITCODE -ne 0) {
    throw "No se pudo generar la blocklist local."
}

$blocklist = Join-Path $repoRoot "data\blocklist.bin"
$blocklistSize = (Get-Item -LiteralPath $blocklist).Length
if (($blocklistSize % 5) -ne 0 -or $blocklistSize -gt 1250000) {
    throw "La blocklist local no cumple formato o tamaño."
}
Get-FileHash -Algorithm SHA256 -LiteralPath $blocklist
```

Después, y solo con aprobación:

```powershell
& $pio run --environment c3 --target uploadfs --upload-port $port
if ($LASTEXITCODE -ne 0) {
    throw "La restauración de LittleFS ha fallado."
}
```

La blocklist mínima sirve únicamente para el laboratorio; no convierte el
mecanismo de actualización de blocklist en seguro.

## Si la placa no arranca

- Si no aparece ningún `COMx`, cambie a un cable de datos conocido, pruebe otro
  puerto USB y repita la secuencia `BOOT` + `RESET`.
- Si el puerto cambia, vuelva a listar dispositivos y use el nuevo `COMx`.
- Si PlatformIO queda esperando conexión, cierre monitores y otras aplicaciones,
  repita el modo ROM y mantenga `BOOT` hasta que la herramienta identifique el
  chip.
- Si el upload finaliza pero la aplicación no arranca, reinicie sin pulsar
  `BOOT`, confirme placa y revisión de origen, y conserve la salida completa de
  PlatformIO.
- Si sospecha corrupción de LittleFS, use la restauración explícita anterior;
  no dependa de `LittleFS.begin(true)` como prueba de recuperación segura.
- Si el fallo persiste, deténgase. No borre toda la flash, no cambie
  `partitions.csv` y no escriba eFuses, secure boot ni flash encryption.

No forman parte de este procedimiento `erase_flash`, targets de borrado total,
instaladores web, OTA de red ni binarios legacy.

## Evidencia HIL pendiente

Cuando el humano autorice la prueba física, registre:

- modelo y revisión exactos de la placa;
- commit, PlatformIO, plataforma/framework y SHA-256 de `firmware.bin`;
- `COMx` antes y durante el modo ROM;
- comando y código de salida de upload;
- reinicio correcto sin `BOOT`;
- recuperación de firmware y, si se autorizó, de LittleFS;
- ausencia de `/update` y del servicio ArduinoOTA;
- cualquier warning o fallo sin ocultarlo.

Hasta completar esa prueba, este documento proporciona un procedimiento
reproducible, pero no demuestra recuperación física ni autoriza un piloto.
