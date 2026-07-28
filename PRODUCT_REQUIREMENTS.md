# Product Requirements — NetShield Mini

## Problema

Usuarios con varios dispositivos quieren reducir anuncios y seguimiento, pero
no saben instalar o mantener Pi-hole, AdGuard Home o extensiones por dispositivo.

## Propuesta

Dispositivo local de bajo consumo basado en ESP32-C3 que actúa como DNS filtrado.
Se configura desde una página local y no requiere app en cada dispositivo.

## MVP 1 incluido

- portal local de configuración Wi-Fi;
- servidor DNS UDP;
- bloqueo mediante hashes en flash;
- DNS upstream configurable;
- allowlist y blocklist local;
- panel local con estado básico;
- contadores agregados;
- actualización manual de blocklist;
- recuperación mediante BOOT;
- watchdog y reconexión;
- documentación en español.

## Fuera del MVP

- bloqueo garantizado de YouTube o Twitch;
- app móvil;
- administración por Internet;
- VPN o DNS-over-HTTPS;
- control parental completo;
- DHCP principal;
- cuentas cloud;
- analítica invasiva;
- venta masiva.

## Requisitos funcionales

- RF-01: modo configuración si no hay red válida.
- RF-02: cerrar AP tras onboarding.
- RF-03: responder y reenviar DNS permitido.
- RF-04: respuesta sinkhole válida para bloqueados.
- RF-05: comprobar sufijos padre según política.
- RF-06: allowlist explícita.
- RF-07: rechazar archivos que excedan partición.
- RF-08: mostrar firmware, blocklist, uptime, RSSI y memoria.
- RF-09: recuperar Wi-Fi automáticamente.
- RF-10: recuperación física.

## Requisitos no funcionales

- compatible con ESP32-C3 4 MB sin PSRAM;
- build reproducible en Apple Silicon;
- sin contraseñas en logs;
- actualización fallida recuperable;
- uso de RAM y flash documentado;
- interfaz usable desde móvil.

## Métricas

- latencia media y p95;
- consultas por segundo;
- heap mínimo;
- reinicios;
- recuperación Wi-Fi;
- uptime;
- falsos positivos;
- estabilidad de alimentación.

## Mensaje permitido

“Reduce publicidad, rastreadores y conexiones no deseadas en los dispositivos de
tu red mediante filtrado DNS local.”

## Mensajes prohibidos

- “Bloquea todos los anuncios.”
- “Elimina los anuncios de YouTube.”
- “Te hace anónimo.”
- “Sustituye a un antivirus.”
- “Protección total.”
