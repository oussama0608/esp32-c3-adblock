# Security Policy and Threat Model

## Activos

Credenciales Wi-Fi, configuración DNS, firmware, blocklist, disponibilidad de
Internet, privacidad DNS y control administrativo.

## Amenazas

1. Toma del panel desde LAN.
2. Blocklist remota maliciosa.
3. OTA no autorizada.
4. Agotamiento de memoria por DNS/HTTP.
5. Registro de navegación sensible.
6. Portal de onboarding abierto.
7. Corrupción por corte eléctrico.
8. Pérdida total de DNS.
9. Secretos publicados en Git.
10. Interfaz accesible desde WAN.

## Controles mínimos

- panel protegido;
- secretos fuera de Git;
- portal temporal;
- sin administración WAN;
- validación estricta;
- límites de archivos y timeouts;
- checksum o firma;
- TLS verificado;
- rollback o recuperación;
- logs agregados;
- rate limiting;
- watchdog;
- tests de DNS malformado.

## Datos

Por defecto no guardar dominios permanentemente, no enviar telemetría, no usar
cloud, mostrar contadores agregados y permitir borrar configuración.
