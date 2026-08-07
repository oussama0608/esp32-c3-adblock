# Política de seguridad

## Estado actual

NetShield Mini está en desarrollo y **todavía no se considera seguro para un
piloto ni para un despliegue doméstico**. No existe una versión de producción
con soporte de seguridad. El firmware actual conserva cinco amenazas CRITICAL,
veinte HIGH y cinco MEDIUM; el registro completo, los tests y las condiciones de
aceptación están en [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

P1 recuperó el build reproducible, P2 endureció y probó el generador host y P3
añadió CI. Esos controles reducen errores de desarrollo, pero no corrigen las
vulnerabilidades del dispositivo. La CI remota solo se considera válida cuando
el humano confirma que `python-quality` y `firmware-build` están verdes para la
revisión exacta.

No se debe flashear el firmware actual a una unidad piloto ni convertirlo en DNS
de una red real. El primer flash de laboratorio queda condicionado a P5.1, a los
gates de `docs/THREAT_MODEL.md` y a aprobación humana explícita.

## Activos protegidos

- credenciales y asociación Wi-Fi;
- firmware, arranque y recuperación física;
- configuración DNS, blocklist, bans y dominios personalizados;
- disponibilidad y corrección del servicio DNS;
- privacidad de consultas, IP, MAC y actividad de clientes;
- control administrativo, flash y heap del dispositivo.

## Cinco bloqueantes principales

1. `/update` y ArduinoOTA aceptan firmware por red sin autorización ni firma; los
   installers rastreados todavía apuntan a un binario anterior con esas vías.
2. El panel y todas sus mutaciones carecen de autenticación, autorización, CSRF
   y defensa contra DNS rebinding.
3. Upload/fetch destruyen primero la blocklist válida, aceptan validación mínima,
   permiten HTTP/`setInsecure()` y exponen SSRF.
4. Dominios y SSID no confiables llegan a JSON/HTML/JavaScript con escape
   incorrecto y permiten XSS.
5. El parser DNS, la asociación upstream, los límites de tasa y el heap no tienen
   todavía tests host, fuzzing ni validación HIL.

## Decisión inmediata de hardening

El primer parche P5 será **P5.1: retirar las dos OTA de firmware por red**:

- eliminar `/update`, sus handlers y el formulario del panel;
- eliminar ArduinoOTA de setup, loop y binario;
- crear perfiles/gates fail-closed y compilar ambos en CI;
- deshabilitar los installers/manifests stale o regenerarlos exclusivamente desde
  el build P5.1 con hash y procedencia; fijar por contenido su tooling web;
- conservar los slots de `partitions.csv` sin modificarlos;
- usar únicamente recuperación/actualización USB con aprobación humana.

La estimación es una reducción de 18–45 KiB de flash y 1,9–2,5 KiB de RAM
estática, pendiente de un build comparativo. Las actualizaciones de blocklist no
se consideran seguras por ello: upload permanece fuera de PILOT hasta P5.2-P5.5
(validación, panel guard y transacción); fetch hasta P5.2-P5.6 (además TLS,
autenticidad y defensa SSRF).

El orden completo P5.1-P5.10 y la comparación A-E están registrados en
`docs/THREAT_MODEL.md`. No se ha implementado ninguno de esos parches en P4.

## Perfiles permitidos

### DEVELOPMENT

Solo para nuestra placa y LAN aislada de pruebas, sin tráfico personal, sin
administración WAN y sin configurarlo como DNS de una red real. Después de P5.1,
OTA de firmware estará compilada fuera. Hasta P5.10 solo se permite un SSID de
laboratorio deliberadamente no sensible, URL de update vacía y ningún capture de
Serial; password, tokens y dominios consultados nunca se registran. P5.10 redacta
también SSID/URL. Flasheo y puerto serie requieren aprobaciones separadas.

### PILOT

No está permitido todavía. Requiere cero amenazas CRITICAL abiertas, todos los
HIGH corregidos o aceptados expresamente con control compensatorio, capacidades
inseguras compiladas fuera, CI real confirmada, fuzzing y HIL, recuperación por
BOOT/USB, pruebas de corte, carga y soak, y política de privacidad/soporte. OTA
de firmware seguirá ausente salvo una decisión posterior con firma y
anti-downgrade. El panel administrativo permanece ausente/read-only salvo que un
canal proteja credencial y sesión; añadir password sobre HTTP claro no basta.

## Invariantes obligatorios

- No guardar SSID, claves, tokens ni credenciales reales en Git, tests o logs.
- No administrar desde Internet ni configurar UPnP, port-forward, DMZ o cloud.
- No usar HTTP remoto ni `setInsecure()` como solución final.
- No activar portal cautivo salvo onboarding o recuperación física temporal.
- No borrar una blocklist válida antes de validar y confirmar su reemplazo.
- No autoformatear un filesystem corrupto ni anunciar un fallo como éxito.
- No aceptar firmware o blocklists sin límites, procedencia y recovery definidos.
- No servir un binario stale ni cargar tooling móvil de un CDN sin pin/SRI o
  vendoring; manifest, hash y fuente deben corresponder.
- No reenviar DNS malformado ni aceptar una respuesta upstream no asociada.
- No conservar historial de dominios ni introducir telemetría por defecto.
- No modificar particiones, eFuses, secure boot o flash encryption sin cálculo,
  plan de recuperación y aprobación humana.
- No afirmar bloqueo total, anonimato, antivirus ni seguridad ya alcanzada.

## Datos y privacidad

La política objetivo es no persistir QNAME ni historial de navegación, no enviar
telemetría y no depender de cloud. Solo se admiten contadores agregados y datos
operativos mínimos con TTL documentado. IP/MAC, URLs y SSID se tratan como datos
sensibles; no deben mostrarse a clientes anónimos ni aparecer completos en logs.
Debe existir un borrado físico verificable de configuración. Las consultas
permitidas hoy salen por UDP claro a Quad9 y son visibles para el resolver y
observadores on-path; esta limitación debe comunicarse y no equivale a privacidad
de transporte.

## Comunicación de vulnerabilidades

No publiques credenciales, datos de usuarios, firmware malicioso funcional ni
detalles explotables que afecten a una unidad desplegada. Si el repositorio
muestra la opción privada **Report a vulnerability**, úsala. Si no existe un
canal privado configurado, contacta primero con el mantenedor sin incluir el
secreto o payload en una issue pública. Las incidencias no sensibles sí pueden
describirse con una reproducción mínima, versión/commit, impacto y resultado
esperado.

Una respuesta o corrección documental no implica que el firmware sea seguro. La
amenaza solo se cierra cuando su test y condición de aceptación pasan en el
perfil afectado.
