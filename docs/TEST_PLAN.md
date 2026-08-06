# Test Plan

Estado a 2026-08-06: no existen tests automatizados. `pytest` devuelve exit 5
con `no tests ran`; completar esta cobertura sigue pendiente y no se considera
un resultado satisfactorio.

## Build
- clone limpio;
- Windows 10 x64;
- blocklist desde cero;
- tamaños dentro de límites;
- sin credenciales.

## Python
- normalización;
- comentarios y duplicados;
- entradas inválidas;
- FNV-1a;
- orden;
- binario;
- colisiones;
- límite de tamaño.

## DNS
- A, AAAA y EDNS;
- paquetes truncados o inválidos;
- compression pointers;
- múltiples preguntas;
- tipos no soportados;
- fuzz básico.

## Integración
- bloqueado;
- permitido;
- upstream caído;
- Wi-Fi perdido;
- blocklist ausente/corrupta;
- actualización interrumpida;
- reinicio durante escritura;
- allowlist.

## Hardware
- alimentación USB desde el host Windows, cargador y router;
- RSSI;
- 24 h y 7 días;
- varios clientes;
- reinicio router;
- cambio Wi-Fi;
- recuperación BOOT.

## Piloto mínimo
- cero reinicios inesperados en 7 días;
- cero secretos;
- recuperación documentada;
- panel protegido;
- versión identificable;
- limitaciones entregadas.
