# devmcast-watch

Catálogo de **grupos multicast de capa 2** de Linux en C++23, zero deps.

Lee `/proc/net/dev_mcast` (exportado por `netdev_mc_seq_show`) y muestra las
direcciones MAC multicast programadas en cada interfaz: IPv4 (`01:00:5e`, RFC
1112), IPv6 (`33:33`, RFC 2464), reserva IEEE (`01:80:c2`) y Cisco
(`01:00:0c`), con `ifindex`, `refcnt`, `global_use` y etiqueta de protocolo.

## Features

- **Fuente única**: `/proc/net/dev_mcast` — una fila por (iface, MAC)
- **Familias**: `ipv4` / `ipv6` / `ieee` / `cisco` / `other` vía `family_of()`
- **Well-known**: All Hosts, All Routers, IGMPv3, mDNS, LLMNR, SSDP, OSPF,
  VRRP, All Nodes, MLDv2, DHCPv6, solicited-node, STP, LACP, LLDP, CDP/VTP
- **Hint**: IPv4 23-bit (`224.x.x.x`), IPv6 últimos 32 bits, solicited-node
  `ff02::1:ffxx:xxxx`
- **Resumen**: entries, ifaces, recuento por familia
- **Filtros**: `--iface`, `--family`, `--global`
- **`--top N`**: ordena por `refcnt` descendente (empates permitidos)
- **Modo watch (`--watch N`)**: refresh periódico con flush por frame
- **Salida JSON (`--json`)**: `summary` + array `groups` validable
- **Demo mode (`--demo`)**: host sintético eth0+wlan0+br0 (14 grupos)
- **`--file`**: parsea un dump (tolera comentarios `#` y filas basura)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 55 checks (clasificación, parser, `/proc` real, demo,
  filtros, --top, JSON, --no-color, escapes)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o devmcast-watch
```

## Usage

```bash
# Snapshot único (host real)
./devmcast-watch

# Solo eth0
./devmcast-watch --iface eth0

# Solo IPv6 (33:33)
./devmcast-watch --family ipv6

# Solo direcciones con global_use
./devmcast-watch --global

# Top 5 por refcnt
./devmcast-watch --top 5

# Modo watch (cada 2s)
./devmcast-watch --watch 2

# JSON
./devmcast-watch --json

# Demo (host sintético dual-stack + bridge)
./devmcast-watch --demo

# Parsear un dump con comentarios
./devmcast-watch --file sample-devmcast.table --no-color

# Sin colores
./devmcast-watch --no-color

# Auto-tests
./devmcast-watch --selftest
```

## Data Source

| Campo | Origen |
|-------|--------|
| `ifindex` | `dev->ifindex` |
| `iface` | `dev->name` (16 chars) |
| `refcnt` | `ha->refcount` |
| `global` | `ha->global_use` |
| `mac` | 12 hex chars, sin `:` (`%02x` × 6) |

- IPv4 mcast MAC = `01:00:5e` + 23 bits bajos del grupo (5 bits se pierden).
- IPv6 mcast MAC = `33:33` + últimos 32 bits de la dirección.
- `solicited-node` = `33:33:ff:XX:XX:XX` ↔ `ff02::1:ffXX:XXXX`.

## License

MIT
