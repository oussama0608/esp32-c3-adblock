# Prompts para Codex

Ejecutarlos uno por uno.

## P0 — Auditoría

```text
Lee AGENTS.md, README_START_HERE.md, PRODUCT_REQUIREMENTS.md, ROADMAP.md,
SECURITY.md y docs/TEST_PLAN.md. Inspecciona todo el repositorio.

No edites firmware, no flashees, no cambies red y no instales paquetes globales.

Crea docs/UPSTREAM_AUDIT.md con:
1. mapa de archivos;
2. flujo DNS;
3. formato y generación de blocklist;
4. particiones y límites;
5. RAM y flash;
6. onboarding, panel y OTA;
7. dependencias;
8. compatibilidad Windows 10 y puertos COM;
9. riesgos de seguridad con archivos y funciones;
10. tests presentes y ausentes;
11. cambios priorizados.

Ejecuta solo lectura y builds no destructivos. Registra comandos y errores.
```

## P1 — Build reproducible

```text
Usa la auditoría. Haz el cambio mínimo para compilar en Windows 10 x64 y
Linux sin rutas serie fijas. No cambies particiones ni flashees.

Añade setup local. Ejecuta generador, pio run y comprobaciones Python.
Muestra diff, resultados, riesgos y propuesta de commit.
```

## P2 — Tests blocklist

```text
Añade pytest con fixtures pequeñas y sin descargar listas reales. Cubre
normalización, comentarios, duplicados, inválidos, hash, orden, binario,
colisiones y límite de tamaño. Refactoriza solo lo necesario. Ejecuta tests y build.
```

## P3 — CI

```text
Crea GitHub Actions con permisos mínimos: tests Python, fixture de blocklist,
build PlatformIO, tamaños de firmware y detección básica de secretos.
No publiques releases, no uses secrets y no hagas push.
```

## P4 — Seguridad

```text
Actualiza SECURITY.md y crea docs/THREAT_MODEL.md. Revisa autenticación, endpoints
destructivos, OTA, uploads, TLS, credenciales, parser DNS, memoria, persistencia,
logs, portal y recuperación. No implementes todo: prioriza parches pequeños.
```

## P5 — Primer parche

```text
Implementa solo el parche de mayor prioridad aprobado. Añade verificación.
No abras WAN, no uses cloud y no flashees. Ejecuta build y tests.
```

## P6 — Primer flasheo

```text
Crea docs/FIRST_FLASH.md para Windows 10 x64: puerto, bootloader, build,
firmware, filesystem, monitor serie y recuperación. No ejecutes el flasheo.
```

## P7 — GO / NO-GO

```text
Revisa el working tree, ejecuta /review si existe, build y tests.
No flashees. Devuelve GO/NO-GO, bloqueantes, comandos que requieren aprobación
y checklist de recuperación.
```
