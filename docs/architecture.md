# Arquitectura — devmcast-watch

## Flujo

```
/proc/net/dev_mcast  ──►  load_catalog()  ──►  Catalog{ts, groups[N]}
                                                    │
                ┌───────────────────────────────────┼───────────────────────────┐
                ▼                                   ▼                           ▼
         render_catalog()                    render_json()                 (watch loop)
         (tabla L2)                          (summary + groups)            re-read N s
```

## Estructura de datos

- `McAddr` — una fila: `ifindex`, `iface`, `refcnt`, `global_use`, `mac[6]`.
- `Family` — enum derivado de los OUI/prefijos MAC (`family_of()`).
- `Catalog` — vector de grupos + agregados (`family_count`, `iface_count`).
- `Filters { iface, family, global_only, top }` — `passes()` + `--top N`
  ordena por **refcnt** descendente.

## Parsing

- Formato kernel (`netdev_mc_seq_show`):
  `"%3d %-16s %-5d %-5d %02x%02x%02x%02x%02x%02x\n"`.
- Comentarios `#` hasta fin de línea; filas malformadas se saltan.
- MAC: exactamente 12 hex chars (case-insensitive) vía `std::from_chars`.

## Clasificación

| Prefijo MAC | Familia | Hint |
|-------------|---------|------|
| `01:00:5e` | ipv4 | RFC 1112, 23 bits → `224.x.x.x` |
| `33:33` | ipv6 | RFC 2464, 32 bits; `33:33:ff` = solicited-node |
| `01:80:c2` | ieee | STP / LACP / 802.1X / LLDP |
| `01:00:0c` | cisco | CDP/VTP, PVST+ |

## Decisiones

- **C++23 stdlib-only**: g++ directo, cero dependencias.
- **L2 vs L3**: `igmp-watch` lista grupos IPv4/IPv6 en `/proc/net/igmp{,6}`;
  este catálogo muestra lo que el NIC tiene programado en hardware (CAM).
- **`--demo`**: eth0 + wlan0 + br0 para cubrir las 4 familias y un
  solicited-node, con `refcnt` variado para `--top`.
