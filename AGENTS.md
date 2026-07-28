# AGENTS.md

## Misión

Desarrollar y endurecer un bloqueador DNS local para ESP32-C3 de 4 MB basado en
`M-Abozaid/esp32-c3-adblock`, preservando la licencia MIT y la atribución.

El producto se llama provisionalmente NetShield Mini. No afirmar que elimina
todos los anuncios. Describirlo como reducción de publicidad, rastreadores y
dominios maliciosos a nivel DNS.

## Entorno

- Host: Windows 10 x64 en MacBook Pro 2011 Intel.
- Firmware: C++ con Arduino framework.
- Build: PlatformIO nativo en Windows.
- Hardware: ESP32-C3 SuperMini, 4 MB flash, sin PSRAM.
- Herramientas auxiliares: Python 3.
- Sistema de archivos: LittleFS.
- Control de versiones: Git y GitHub.

## Reglas

1. Inspeccionar antes de editar.
2. Hacer cambios pequeños y revisables.
3. Explicar la causa antes de aplicar una solución.
4. Ejecutar pruebas y build después de cambios relevantes.
5. No ocultar errores, warnings o tests fallidos.
6. No añadir dependencias de producción sin justificar tamaño y mantenimiento.
7. No cambiar particiones sin calcular impacto en firmware, OTA y blocklist.
8. No eliminar ni alterar licencia MIT o atribución.
9. No almacenar SSID, Wi-Fi, claves o tokens en Git.
10. No habilitar administración desde Internet.
11. El portal de configuración solo debe existir durante onboarding o recuperación.
12. Interfaz de usuario en español claro; código y nombres técnicos en inglés.
13. Validar todas las entradas de red y archivos.
14. Documentar decisiones en `docs/DECISIONS.md`.

## Requieren aprobación humana

- Flashear una placa.
- Cambiar DNS, DHCP, Wi-Fi o router.
- Instalar paquetes globales.
- Ejecutar comandos destructivos o borrar archivos.
- Cambiar particiones o escribir eFuses.
- Publicar release, hacer push, merge o abrir PR.
- Añadir dependencia de producción.
- Introducir telemetría o servicios externos.

## Seguridad

- Nunca usar credenciales reales en código, logs, tests o documentación.
- No utilizar TLS inseguro como solución final.
- Validar tamaño, formato y autenticidad de firmware y blocklists.
- Limitar panel a LAN y proteger funciones administrativas.
- Aplicar límites de tamaño y tiempo.
- Tratar DNS y archivos subidos como no confiables.
- No guardar historial completo de navegación.
- No prometer anonimato, antivirus ni bloqueo total.

## Verificación base

```bash
python3 tools/build_blocklist.py data/blocklist.bin
pio run
```

Cuando existan:

```bash
pytest -q
ruff check .
```

## Definición de terminado

- build pasa;
- tests pasan;
- no hay secretos;
- documentación coincide;
- se resume el diff;
- se enumeran riesgos;
- se propone un commit sin ejecutarlo sin aprobación.


## Reglas específicas de Windows

- Usar comandos de PowerShell, no Bash, salvo que el humano lo solicite.
- Los puertos serie son `COMx`; no fijar `/dev/ttyACM0` ni `/dev/cu.*`.
- Preferir detección automática de PlatformIO.
- No usar WSL para flashear en el MVP.
- No instalar drivers de terceros sin identificar antes el dispositivo USB.
- No cambiar políticas globales de PowerShell de forma permanente.
