# Notas para Windows 10

## Build local y reproducible

La combinación validada es Python 3.13.12, PlatformIO Core 6.1.19 y la
plataforma `pioarduino` 55.03.37. Ese release fija Arduino-ESP32 3.3.7 y las
librerías correspondientes de ESP-IDF 5.5.2; coincide con las versiones
identificadas en el firmware upstream auditado. `pioarduino` admite Python
3.10–3.13 en Windows; Python 3.14 no es compatible con este release.

Preparación única del Core local, sin instalar paquetes globales:

```powershell
$repoRoot = (Resolve-Path -LiteralPath ".").Path
$env:PLATFORMIO_CORE_DIR = Join-Path $repoRoot ".platformio"
$env:PIP_CACHE_DIR = Join-Path $env:PLATFORMIO_CORE_DIR "pip-cache"
$python = Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"
$coreVenv = Join-Path $env:PLATFORMIO_CORE_DIR "core-venv"
& $python -m venv $coreVenv
& (Join-Path $coreVenv "Scripts\python.exe") -m pip install "platformio==6.1.19"
```

Para cada build, establecer `PLATFORMIO_CORE_DIR` antes de iniciar PlatformIO
evita que el Core intente crear estado o instalar paquetes en el perfil del
usuario:

```powershell
$repoRoot = (Resolve-Path -LiteralPath ".").Path
$env:PLATFORMIO_CORE_DIR = Join-Path $repoRoot ".platformio"
$pio = Join-Path $env:PLATFORMIO_CORE_DIR "core-venv\Scripts\pio.exe"
& $pio run
```

La carpeta `.platformio/` está ignorada por Git. PlatformIO instala allí la
plataforma, el framework y el toolchain fijados que necesita el build; no hace
falta una instalación global. El release 55.03.37 requiere PlatformIO Core
6.1.18 o posterior y se ha verificado con 6.1.19. Si se usa otra versión
compatible de Python, hay que ajustar la ruta de `$python` durante la preparación.

`src/secrets.h` es opcional y permanece ignorado. Si no existe, el firmware se
compila con SSID y contraseña vacíos y entra en onboarding al no encontrar
credenciales provisionadas.

## Puerto serie

El ESP32-C3 aparecerá normalmente como `COM3`, `COM4` u otro `COMx`.

Listar con:

```powershell
$repoRoot = (Resolve-Path -LiteralPath ".").Path
$env:PLATFORMIO_CORE_DIR = Join-Path $repoRoot ".platformio"
$pio = Join-Path $env:PLATFORMIO_CORE_DIR "core-venv\Scripts\pio.exe"
& $pio device list
```

PlatformIO puede detectar automáticamente el puerto si `upload_port` no está
fijado en `platformio.ini`.

## Flasheo futuro

P5.1 retiró la actualización de firmware por red y deshabilitó los instaladores
web legacy. El procedimiento completo y sus condiciones están en
[USB_RECOVERY_WINDOWS.md](USB_RECOVERY_WINDOWS.md).

No ejecutar hasta contar con aprobación humana y cumplir sus gates:
la guía enlazada separa build, upload de firmware, restauración destructiva de
LittleFS y monitor serie. `uploadfs` y `device monitor` requieren decisiones y
aprobaciones independientes; no deben ejecutarse como una secuencia automática.

## Si no aparece ningún COM

1. Cambiar el cable USB-C por uno de datos.
2. Probar otro puerto USB.
3. Abrir Administrador de dispositivos.
4. Revisar `Puertos (COM y LPT)` y dispositivos desconocidos.
5. Identificar el chip o interfaz antes de instalar un driver.
6. Probar BOOT + RESET únicamente cuando llegue la fase de flasheo.
