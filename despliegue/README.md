# Despliegue automático (LXC en Proxmox o Debian)

[English](README.en.md) · **Castellano**

Dos scripts para dejar el analizador funcionando sin seguir el README a mano. Simulan por defecto: sin `--ejecutar` solo
muestran lo que harían.

- `crear-lxc.sh` (en el nodo Proxmox, como root): descarga la plantilla Debian 13 si falta, crea un LXC sin privilegios
  con DHCP, sube `instalar.sh` y este mismo repositorio y los ejecuta dentro.
- `instalar.sh` (como root, en el LXC o en cualquier Debian 12/13): instala paquetes y Ollama, descarga el modelo,
  copia el código a `/home/analista/analista-correo`, deja tu `buzon.env` en 600, ejecuta las pruebas y crea un temporizador
  de systemd que lanza `run.sh` cada 2 minutos.

## Lo único que tienes que poner

1. Tu buzón: `cp buzon.env.example buzon.env` y edítalo (servidor, usuario, contraseña, `MX_BUZON`, `REMITENTES`). Se
   rechaza si conserva los valores de ejemplo. La contraseña viaja por fichero, nunca por línea de comandos.
2. Los parámetros del contenedor, si no te valen los de por defecto:

| Opción | Por defecto | Para qué |
|---|---|---|
| `--modelo` | `qwen2.5:7b` | Modelo de Ollama. Con más memoria o GPU, uno mayor (p. ej. `qwen2.5:14b`; mira tamaños en [ollama.com/library](https://ollama.com/library)); `qwen2.5:3b` si vas justo (licencia Qwen Research: solo investigación o evaluación; el 7b y el 14b son Apache-2.0). |
| `--memoria` / `--nucleos` / `--disco` | 8192 MiB / 4 / 24 GB | Sube la memoria con un modelo mayor: el modelo cabe en RAM además del sistema. |
| `--vmid`, `--nombre` | siguiente libre, `analista-correo` | Identificador y nombre del CT. |
| `--almacen`, `--plantillas`, `--puente` | `local-lvm`, `local`, `vmbr0` | Almacenes y red de tu Proxmox. |
| `--onboot` | no | Arrancar el CT con el nodo. |
| `--fuente` | este repositorio | Un `.tgz` o una URL `https://` git, si quieres desplegar otra copia. |

```
cp buzon.env.example buzon.env      # edítalo
./despliegue/crear-lxc.sh --env buzon.env --modelo qwen2.5:14b --memoria 16384            # simula
./despliegue/crear-lxc.sh --env buzon.env --modelo qwen2.5:14b --memoria 16384 --ejecutar
```

Sin `--env` todo se instala pero el temporizador queda sin activar: edita `~/.config/analista-correo/buzon.env` dentro del
CT (usuario `analista`) y activa `systemctl enable --now analista-correo.timer`.

## Cambiar el modelo después

El modelo lo lee la variable de entorno `ANALISTA_CORREO_MODELO` (también en `analizar_correo.py` y `buzon.py` a mano). El
temporizador la lleva en `/etc/systemd/system/analista-correo.service`: cambia esa línea, `systemctl daemon-reload` y
`ollama pull <modelo>`. Los correos ya analizados no se reanalizan solos con el modelo nuevo.

## Qué tarda y qué toca

Unos 18 minutos la primera vez (aprox.; medido en un Xeon E5-2620 v1 con 4 vCPU y sin GPU: Ollama y el modelo ~9 min, pruebas y primer análisis con el modelo en
frío el resto); `instalar.sh --sin-prueba` se salta la última parte. Cada correo tarda 1-2 minutos solo con CPU (aprox.). Dentro del
CT toca: paquetes de Debian, el usuario `analista`, Ollama (se instala con su script oficial, `https://ollama.com/install.sh`,
sin verificar hash), el código, el `buzon.env` y las dos unidades systemd. Para deshacerlo: `pct stop <id>; pct destroy <id> --purge`.
Si falla con el CT creado, el script lo dice. Probado en Proxmox VE 9 con Debian 13.

## Actualizar el código

El instalador no sobrescribe una instalación completa. Para actualizar, copia los ficheros nuevos sobre `/home/analista/analista-correo` (la configuración, `~/.config/analista-correo/`, y los datos, `~/.local/state/analista-correo/`, están fuera de esa carpeta y no se tocan) o repite el despliegue en un CT nuevo. Si una instalación quedó a medias, el instalador lo dice: borra la carpeta y repite.
