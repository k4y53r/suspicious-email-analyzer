# Automatic deployment (Proxmox LXC or Debian)

**English** · [Castellano](README.md)

Two scripts that leave the analyzer running without following the main README by hand. They simulate by default: without
`--ejecutar` they only print what they would do.

- `crear-lxc.sh` (on the Proxmox node, as root): downloads the Debian 13 template if missing, creates an unprivileged LXC
  with DHCP, uploads `instalar.sh` and this very repository, and runs them inside.
- `instalar.sh` (as root, inside the LXC or any Debian 12/13): installs packages and Ollama, pulls the model, copies the
  code to `/home/analista/analista-correo`, leaves your `buzon.env` with mode 600, runs the tests and creates a systemd
  timer that runs `run.sh` every 2 minutes.

## All you have to provide

1. Your mailbox: `cp buzon.env.example buzon.env` and edit it (server, user, password, `MX_BUZON`, `REMITENTES`). It is
   rejected if it still holds the example values. The password travels by file, never on the command line.
2. The container parameters, if the defaults do not suit you:

| Option | Default | What for |
|---|---|---|
| `--modelo` | `qwen2.5:7b` | Ollama model. With more memory or a GPU, a larger one (e.g. `qwen2.5:14b`; see sizes at [ollama.com/library](https://ollama.com/library)); `qwen2.5:3b` if memory is tight (Qwen Research license: research or evaluation only; the 7b and 14b are Apache-2.0). |
| `--memoria` / `--nucleos` / `--disco` | 8192 MiB / 4 / 24 GB | Raise the memory with a larger model: the model must fit in RAM next to the system. |
| `--vmid`, `--nombre` | next free id, `analista-correo` | Container id and name. |
| `--almacen`, `--plantillas`, `--puente` | `local-lvm`, `local`, `vmbr0` | Storage and network of your Proxmox. |
| `--onboot` | no | Start the container with the node. |
| `--fuente` | this repository | A `.tgz` or an `https://` git URL, to deploy another copy. |

```
cp buzon.env.example buzon.env      # edit it
./despliegue/crear-lxc.sh --env buzon.env --modelo qwen2.5:14b --memoria 16384            # simulates
./despliegue/crear-lxc.sh --env buzon.env --modelo qwen2.5:14b --memoria 16384 --ejecutar
```

Without `--env` everything is installed but the timer stays disabled: edit `~/.config/analista-correo/buzon.env` inside
the container (user `analista`) and enable it with `systemctl enable --now analista-correo.timer`. `instalar.sh` can also
be run on its own on any Debian 12/13 machine (`--fuente` defaults to this repository).

## Changing the model later

The model is read from the `ANALISTA_CORREO_MODELO` environment variable (also usable by hand with `analizar_correo.py` and
`buzon.py`). The timer carries it in `/etc/systemd/system/analista-correo.service`: change that line, run
`systemctl daemon-reload` and `ollama pull <model>`. Mails already analysed are not re-analysed automatically with the
new model.

## Time and what it touches

About 18 minutes the first time (approx.; measured on a Xeon E5-2620 v1 with 4 vCPU and no GPU: Ollama and the model ~9 min; tests and the first analysis with the
cold model the rest); `instalar.sh --sin-prueba` skips the last part. Each mail takes 1-2 minutes on CPU only (approx.). Inside the
container it touches: Debian packages, the `analista` user, Ollama (installed with its official script,
`https://ollama.com/install.sh`, without hash verification), the code, `buzon.env` and the two systemd units. To undo it:
`pct stop <id>; pct destroy <id> --purge`. If it fails with the container already created, the script says so. Tested on
Proxmox VE 9 with Debian 13.
