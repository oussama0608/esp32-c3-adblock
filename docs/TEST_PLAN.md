# Test Plan

Estado a 2026-08-06: P2 incorpora 47 casos `pytest` con fixtures locales,
pequeñas y deterministas. La última ejecución terminó con `47 passed` y cero
fallos tanto con el intérprete de pruebas disponible como con Python 3.13. Los
tests no descargan blocklists ni acceden a Internet: `urlopen` está bloqueado
por defecto y la única descarga simulada usa bytes locales controlados.

## Build

P2 no añade tests automatizados del firmware. `pio run` sigue siendo la puerta
de verificación del build nativo de Windows; deben registrarse su código de
salida, warnings y tamaños de RAM y flash en cada entrega.

## Python — implementado en P2

- lectura de una entrada de dominio por línea y de hosts con `0.0.0.0` o
  `127.0.0.1`;
- comentarios, líneas vacías y duplicados;
- normalización a minúsculas, retirada de puntos extremos, prefijo `www.` y
  wildcard inicial según la política vigente (`*.example.com` se convierte en
  `example.com`);
- rechazo de sintaxis inválida, literales IP, dominios de más de 253 caracteres
  y labels DNS de más de 63 caracteres, incluidos sus valores límite;
- FNV-1a de 64 bits truncado a 40 bits con cuatro vectores conocidos;
- serialización en cinco bytes little-endian, orden numérico ascendente y
  eliminación de hashes duplicados;
- colisiones forzadas de dominios distintos: deduplicación del hash, conteo y
  reporte en la salida de la CLI;
- tamaño del archivo binario múltiplo de cinco y rechazo de blobs desalineados;
- límite máximo configurable mediante `--max-bytes`, incluido el borde exacto
  permitido y el rechazo sin reemplazo al excederlo;
- lectura local y descarga HTTP simulada sin tráfico de red;
- fallo parcial de fuentes con aprovechamiento de una fuente válida;
- fallo total de fuentes con salida distinta de cero, sin crear un blob vacío y
  preservando una blocklist anterior;
- fuente legible sin dominios válidos: fallo y preservación del destino;
- temporal completo en el mismo directorio, cerrado antes de `os.replace`, y
  limpieza del temporal si falla el reemplazo.

## Python — pendiente

- vectores compartidos con un harness C++ que compruebe paridad exacta con el
  hash del firmware;
- property-based testing o fuzz del parser de listas;
- pruebas de corte del proceso o alimentación durante la sustitución y de la
  semántica atómica en todos los filesystems soportados;
- validación de procedencia, revisión y autenticidad de fuentes reales, sin
  convertir las descargas de Internet en requisito de pytest.

## DNS — pendiente

- A, AAAA y EDNS;
- paquetes truncados o inválidos;
- compression pointers;
- múltiples preguntas;
- tipos no soportados;
- fuzz básico.

## Integración — pendiente

- bloqueado;
- permitido;
- upstream caído;
- Wi-Fi perdido;
- blocklist ausente o corrupta;
- actualización interrumpida;
- reinicio durante escritura;
- allowlist.

## Hardware — pendiente

- alimentación USB desde el host Windows, cargador y router;
- RSSI;
- 24 horas y 7 días;
- varios clientes;
- reinicio router;
- cambio Wi-Fi;
- recuperación BOOT.

## Piloto mínimo — pendiente

- cero reinicios inesperados en 7 días;
- cero secretos;
- recuperación documentada;
- panel protegido;
- versión identificable;
- limitaciones entregadas.
