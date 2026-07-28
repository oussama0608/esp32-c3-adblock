# Notas para Windows 10

## Puerto serie

El ESP32-C3 aparecerá normalmente como `COM3`, `COM4` u otro `COMx`.

Listar con:

```powershell
pio device list
```

PlatformIO puede detectar automáticamente el puerto si `upload_port` no está
fijado en `platformio.ini`.

## Flasheo futuro

No ejecutar hasta completar las fases P0-P7:

```powershell
pio run
pio run --target upload
pio run --target uploadfs
pio device monitor --baud 115200
```

Si hay varios puertos:

```powershell
pio run --target upload --upload-port COM4
```

## Si no aparece ningún COM

1. Cambiar el cable USB-C por uno de datos.
2. Probar otro puerto USB.
3. Abrir Administrador de dispositivos.
4. Revisar `Puertos (COM y LPT)` y dispositivos desconocidos.
5. Identificar el chip o interfaz antes de instalar un driver.
6. Probar BOOT + RESET únicamente cuando llegue la fase de flasheo.
