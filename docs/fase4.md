# Fase 4: estado (2026-09-30, cerrada)

Rama `fase4` sobre `main` (24cc44c). Hitos: M23 8716817, M24 dad3ef8, M25 f218135, M26 062060e, M27 (este documento).
Smoke verde:
- erista y mariko × {empty, core, ams, stock} × {image, dir}: 244 PASS. Los únicos 16 FAIL eran las comprobaciones
  del adaptador en las celdas cortas; el adaptador se enumera tras el diálogo de potencia con psm, así que pasaron
  a `--long`.
- ams/stock `--long` en los dos SoC (erista ams dir, erista stock dir, mariko ams dir, mariko stock image).

Sin ejecutar al cerrar, por falta de tiempo: ams `--eth none --long`, `--maintenance` y `tools/hvm_leakscan.py`.
Pendiente: la opción de Internet real (`--net internet` con passt), preparada pero sin aplicar ni probar.

## Frontera al cerrar la fase
- USB-C en OTG:
  - el BM92T36 informa de un dispositivo sin PD;
  - `usb` pide VBUS a psm (ReplyPowerRequest), enciende la fuente (CONFIG1 SPDSRC) y arranca el host XUSB;
  - el Falcon es HLE y el xHCI de QEMU enumera el ASIX AX88772;
  - `eth` lo maneja y nifm lo usa: DHCP 10.0.2.15 de `tools/hvm_net.py` y, en el test de conexión,
    `ctest.cdn.nintendo.net` recibe NXDOMAIN.
  - nifm reintenta la conexión cada 20–60 s. Nada sale del host.
- account construye `idgen:/context.bin` y ams y stock no tienen caídas (tampoco la cascada de fatales de F3).
- La frontera de account de F3 era una carrera y no la falta de interfaz:
  - account pregunta por las interfaces en su primer arranque; nifm ya contesta, pero su hilo de interfaces (baja
    prioridad, creado antes) aún no había corrido;
  - FS completaba los comandos eMMC al instante y no dejaba dormir al core 3.
  - Con la latencia de SD/eMMC, el hilo corre antes, y account pasa incluso con `--eth none` (nifm lista la WLAN
    con la MAC del CAL0 aunque no haya tarjeta PCIe).
- Sin Internet (NXDOMAIN): los servicios de red (npns, bcat, nim, account en línea) se quedan esperando conexión.
- El core 3 sigue sin quedar ocioso (nvservices sin GPU, hid, audio).

## Herramientas de depuración
- `run.sh --trace` también activa eventos de trace de QEMU de los modelos nuevos (`bm92t36_*`, `usb_xhci_*`,
  `usb_port_*`, `usb_asix_*`…) en `qemu-<soc>.log`. `hvm_log.py` los separa de los registros de `-d int` y los
  resume en «Device events».
- `HVM_OTG_DEVICE="usb-kbd"`: enchufa un dispositivo USB de QEMU por OTG en vez del adaptador.
- `HVM_NET_PCAP=<fichero>`: `hvm_net` captura el tráfico del adaptador. Su log de eventos (privado, 0600) está en
  `~/.horizonvm/logs/net-<soc>.log`.
- Lo de F3 sigue valiendo: `HVM_TRACE_ARGS=watch_pid=N,...`, `bt=` en las peticiones a `sm`, IDA sobre ELF en
  `~/.horizonvm/tmp/re`, `set print frame-arguments none` y `tools/hvm_leakscan.py`.

## Normas
Las de F3 no cambian:
- no parchear Atmosphère;
- parches neutros de tegra_qemu (0004–0008 modelan hardware que faltaba);
- un commit `Mx:` por hito, sin push;
- secretos solo en `~/.horizonvm`;
- el firmware de Nintendo nunca entra en el repo;
- consultar al usuario las decisiones de diseño.

## Cambios respecto al plan aprobado
- **M23 (PD):**
  - `usb` consulta el alta de OTG antes de que psm haya habilitado sus peticiones de potencia y no la reevalúa. En
    el modelo, VBUS (STATUS1 VSAFE) depende de CONFIG1 SPDSRC (apagado tras el reset), y encenderlo vuelve a
    notificar el enchufe (PLUGPULL).
  - PdRstN (GPIO V5) reinicia el modelo; por eso la GPIO tiene también líneas de salida.
  - `INT_STA` de nivel sigue al nivel. Retenido provocaba una tormenta de alertas.
- **M23/M24:** el host XUSB no arranca sin nada insertado, así que son commits separados. Se verificaron a mano
  con `HVM_OTG_DEVICE=usb-kbd` en Erista (y, con el adaptador, en la matriz final de los dos SoC). La matriz
  completa se ejecutó una vez, sobre el estado de M27.
- **M24:**
  - `usb` exige el device ID 0x0FAC en FPCI `CFG_0`;
  - el mailbox responde ACK a `MSG_ENABLED` por SMI (IRQ 40), porque el siguiente envío espera a `OWNER`=0;
  - el driver xHCI de Horizon es genérico (lee CAPLENGTH/DBOFF/RTSOFF, admite CSZ 32/64) y no hizo falta tocar
    `hcd-xhci.c`.
- **M25:**
  - endpoints según la tabla de `eth`: 0x81 interrupción, 0x82 bulk IN, 0x03 bulk OUT (el plan decía 0x83/0x02);
  - `CLEAR_FEATURE(ENDPOINT_HALT)` se acepta;
  - RX: una trama por transferencia (el parser de `eth` no admite relleno entre tramas).
- **M25/M26:** con el adaptador y DHCP funcionando, account seguía abortando: la carrera de arriba.
- **M27 (decisión del usuario):** latencia de SD/eMMC realista en el SDHCI (parche 0008):
  - eMMC: 50 µs por comando + 4 µs/KiB;
  - SD: 100 µs + 40 µs/KiB.
  - Mientras tanto, FS duerme en la IRQ y el resto del core 3 avanza. Consecuencia: `--eth none` ya no reproduce
    la frontera de F3.
- **M27:** con los nuevos tiempos, ns hacía la «actualización de tarjeta para autoarranque» y abortaba con
  2002-2667 (GameCardSplFailure). La detección de tarjeta (GPIO S3, activa a nivel bajo) leía 0, «insertada».
  `run.sh` la pone en alto: ranura vacía (como los botones de volumen en F3).
- **M27:** el smoke espera cero caídas en ams/stock, comprueba PD, XUSB y AX88772 en la ejecución corta y
  DHCP/DNS en `--long`. Su lectura del monitor espera el prompt (con QEMU ocupado se perdía alguna respuesta).
- **Red:** el QEMU compilado no tiene libslirp, así que `hvm_net` va por `-netdev stream` y nunca abre sockets
  INET. El adaptador está conectado por defecto en ams/stock; `--eth none` lo quita.
- **Decisiones del usuario:** AX88772, OTG en portátil, `hvm_net` aislado, adaptador por defecto, latencia
  eMMC realista.

## Plan aprobado (original, sin modificar)


## Contexto

F3 está en `main` (24cc44c). La frontera es esta:
- `account` aborta al construir `idgen:/context.bin`, porque `nifm:s` EnumerateNetworkInterfaces devuelve 0
  interfaces: la WLAN por PCIe no está emulada y no hay Ethernet USB.
- En stock, su `fatal:u` arrastra en cascada a pcv, vi, Bus, hid, FS…

**Objetivo de F4:**
- Horizon ve un adaptador Ethernet USB.
- nifm tiene interfaz y obtiene IP.
- account pasa.

Todo en Erista y Mariko, en ams y stock.

**Decisiones del usuario**
- Adaptador: **ASIX AX88772** (0b95:7720, USB 2.0 high-speed, 100 Mb/s), como modelo nuevo de QEMU.
- Conexión: **OTG en portátil**. El BM92T36 informa de un dispositivo USB-C sin PD; la consola es DFP y da VBUS.
- Backend: **`tools/hvm_net.py` aislado** (`-netdev stream`):
  - ARP, DHCP, ICMP y DNS que contesta NXDOMAIN;
  - nada sale del host;
  - el test de conexión de nifm falla.
- **Conectado por defecto en ams/stock** en cuanto exista el adaptador (M25); `--eth none` reproduce la frontera
  de F3.

**Normas que siguen:**
- no parchear Atmosphère; parches neutros de tegra_qemu solo por hardware que falta;
- binarios de Nintendo solo en `~/.horizonvm/tmp/re`; secretos solo en `~/.horizonvm`;
- un commit `Mx:` por hito verificado en la rama `fase4`, sin push;
- documentar lo justo;
- consultar las decisiones de diseño.

## Hallazgos que fijan el diseño

**eth** (22.5.0) acepta exactamente estos VID:PID:
- 0b95:1790 y 2001:4a00 (AX88179);
- **0b95:7720 (AX88772)**;
- 0bda:8153 y 057e:201b (RTL8153).

El driver AX88772 es pequeño (~27 funciones) y usa las peticiones vendor ASIX clásicas.

**usb** (Nintendo)
- PlatformConfig: `port_count=1`, `DualRole`, `is_pd_capable=1`, `hs_lane=0`, `ss_lane=0`, `soc_name` T210/T214.
- Incluye dos firmwares Falcon `XUSBFW` y abre por I2C el BM92T36 y el BQ24193.
- **Qué hace hoy:**
  - lee los registros 0x4E, 0x03, 0x04, 0x18, 0x28, 0x2B y 0x02 del BM92T;
  - manda `SYS_RESET` (0x0D0D) ocho veces consultando STATUS1, que siempre vale 0;
  - **nunca toca el host XUSB.**

**BM92T36**, según el driver L4T `bm92txx.c` (CTCaer):
- Inserción OTG: STATUS1 `INSERT|SRC_MODE|DR=DFP`, STATUS2 `OTG_INSERT`, ALERT `PLUGPULL`.
- Los comandos terminan con `ALERT_CMD_DONE` / `LASTCMD`.
- La alerta va por GPIO **K4 (CradleIrq)**, activa a nivel bajo: línea 84, banco 2, `INT_GPIO3`.

**tegra_qemu**
- `tegra.xusb` es el xHCI sysbus de QEMU en 0x70090000 (0x4000):
  - puertos como en el T210: el USB2 del puerto 0 es el puerto xHCI 5;
  - bus `usb-bus.2`;
  - FPCI 0x70098000 e IPFS 0x70099000 **sin mapear**: no hay Falcon, CSB ni mailbox;
  - la IRQ SMI (SPI 40) no está cableada;
  - el DMA no pasa por la SMMU, aunque `tegra_mc_get_iommu_address_space(XusbHost)` existe;
  - bug: `slots=1`/`intrs=1`, porque `object_initialize_child` pisa los valores por defecto.
- **GPIO:** la entrada solo viene de `reset-value-*` y las IRQ de banco nunca se elevan.
- **I2C1:** BM92T36 (0x18) y BQ24193 (0x6B) son `dummyi2c`.
- **Red:** QEMU no tiene libslirp (no hay `-netdev user`), pero sí `-netdev stream` (trama con longitud BE de
  4 bytes).
- `usb-net` es CDC full-speed: solo sirve de plantilla de fontanería.

## Diseño transversal

**Parches** (línea de descripción + `git diff`, incrementales sobre los anteriores para que `bootstrap.sh` detecte los
ya aplicados):
- `patches/tegra_qemu/0004-gpio-input-lines-and-interrupts.patch`
- `0005-bm92t36-usb-pd.patch`
- `0006-xusb-host-hle.patch`
- `0007-usb-ax88772.patch`

Los dispositivos nuevos van en `hw/misc`/`hw/usb` con Kconfig, meson y `trace-events`.

**Mandos de `run.sh`**
- `--eth ax88772|none`:
  - el valor por defecto pasa a `ax88772` en ams/stock desde M25;
  - siempre `none` en empty/core.
- `HVM_OTG_DEVICE="<spec -device>"`: variable solo de depuración para el arranque manual de M23/M24 (p. ej.
  `usb-kbd`). Pone el BM92T36 en `otg` y conecta ese dispositivo en `bus=usb-bus.2,port=1`.
- `hvm_smoke` hereda el entorno y gana `--eth`.

**Observabilidad**
- **Invitado** (MMIO de GPIO/I2C/XUSB e IPC de `usb:hs`/eth/nifm): hvmtrace, como hasta ahora.
- **Dispositivos:** eventos de trace de QEMU de baja frecuencia con `--trace` (`usb_xhci_run`, `usb_port_attach`,
  `usb_xhci_slot_*`, `usb_set_config`, `bm92t36_*`, `usb_asix_*`).
- **Conexión:** `info usb` por el monitor en el smoke (producto, puerto 1, 480 Mb/s).
- **Arreglo en `hvm_log`:** separa esas líneas de trace antes de `EXC_RE`, porque pueden partir los registros
  multilínea de `-d int`. Lleva test.

**Coste**
- Bucle interno: una celda con `--trace` + `hvm_log.py`.
- Tras tocar un parche: celdas empty/core (segundos).
- Matriz completa (~1,5–2 h en segundo plano): solo al cerrar cada hito.

## Hitos (rama `fase4` desde `main`)

### M23: GPIO con interrupciones y BM92T36 (primero RE)

**1. RE con IDA** (extraer `usb` a `~/.horizonvm/tmp/re`)
- **Init PD:**
  - IDs y registros de firmware esperados;
  - qué espera `SYS_RESET` (ALERT `CMD_DONE`, `LASTCMD`/`CMD_BUSY` o el evento de K4 con timeout);
  - cómo se limpia ALERT.
- **Modo de interrupción** de K4 que programa Bus.
- **Camino OTG:**
  - escrituras al BQ24193 y si relee `VBUS_STAT`;
  - GPIO J5/L0/K5;
  - overrides de VBUS/ID en padctl;
  - si STATUS1 debe mostrar `SPDSRC1`/`VSAFE`.
- **Init XusbHost** (para M24): accesos FPCI/CSB/mailbox, esperas en CAR/PMC/padctl y supuestos sobre el xHCI
  (CAPLENGTH, **CSZ**, xECP, puertos, slots).
- **Pregunta clave:** si `usb` arranca el host XUSB aunque no haya nada insertado. En ese caso M23 y M24 van en un
  solo commit (ver decisiones).

**2. Parche 0004 (`hw/arm/tegra2/ppsb/gpio/gpio.c`)**
- `qdev_init_gpio_in` con 256 líneas (línea = puerto×8+pin); nivel y bandera "conducido" por pin, en el vmstate.
- `GPIO_IN = (reset & ~driven) | (level & driven)`.
- Solo en los pines conducidos:
  - semántica de `INT_LVL` (polaridad, flanco, ambos flancos) e `INT_STA`/`INT_CLR`;
  - el nivel se vuelve a retener mientras siga activo, incluidos los registros enmascarados;
  - IRQ de banco = OR de `INT_STA & INT_ENB & CNF`.
- Los pines no conducidos no cambian: así se evitan tormentas de interrupciones.

**3. Parche 0005 (`hw/misc/bm92t36.c`)**
- Registros de 16 bits LE; los bloques (0x08, 0x20, 0x23, 0x28, 0x2B, 0x50, 0x60) llevan byte de cuenta.
- Propiedad `state=none|otg`.
- `COMMAND`:
  - `SYS_RESET` → `CMD_DONE` (+`PLUGPULL` en `otg`), `LASTCMD=COMPLETE`;
  - el resto, según el RE.
- Salida `alert` activa a nivel bajo, conectada a la línea 84 de la GPIO en `tegrax1.c` (sustituye al `dummyi2c`
  0x18 de `tegrax1.c:1296`).
- IDs y firmware como propiedades con los valores del RE.
- Modelo mínimo del BQ24193 (`VBUS_STAT` sigue a `CHG_CONFIG`) solo si el RE muestra que se relee.

**4. Herramientas**
- `hvm_log` DEVICES: `xusb_host` (0x70090000, 0xA000) y `xusb_dev`.
- Filtro de las líneas de trace.
- Tests.

**5. Verificación**
- Con `none` (valor por defecto), la matriz queda verde.
- Nueva comprobación en ams/stock: un solo `SYS_RESET` completa y Bus atiende la alerta de K4 (escritura a
  `INT_CLR` 0x6000D278), sin los 8 reintentos.
- Manual con `HVM_OTG_DEVICE=usb-kbd` en los dos SoC: `usb` activa el OTG y hace su primer acceso a `xusb_host`.

### M24: host XUSB (HLE del Falcon, parche 0006)

**Mapa**
- Contenedor `tegra.xusb_host` de 0xA000 bytes:
  - xHCI en 0;
  - hueco que lee 0 hasta 0x8000;
  - FPCI en 0x8000;
  - IPFS en 0x9000.
- La entrada tz-ppc del puerto 12 apunta a ese contenedor.

**FPCI**
- Cabecera PCI: ID 0x10DE, `CFG_1`, BAR0.
- Mailbox (0xE4/0xE8/0xEC/0xF0) y `ARU_SMI_INTR` (0x428, W1C).
- `CSBRANGE` (0x41C) + ventana CSB 0x800–0x9FF.

**CSB/Falcon (HLE)**
- `ILOAD_BASE_LO` a 0 en el reset (el host lo usa para saber si ya hay firmware).
- `L2IMEMOP_TRIG` → `RESULT.VLD`.
- `CPUCTL STARTCPU` → en marcha.
- El resto se almacena; nunca se lee el firmware.

**Mailbox (HLE)**
- Consume `DATA_IN`.
- Responde `ACK` solo a los comandos que el RE diga que el host espera: `DATA_OUT`, `DEST_SMI`, IRQ SPI 40 por una
  salida con nombre `smi`.
- Registra con `LOG_GUEST_ERROR` los comandos desconocidos.

**Resto del parche**
- IPFS como fichero de registros.
- DMA: `xhci.as = tegra_mc_get_iommu_address_space(XusbHost)`.
- `numslots=64`/`numintrs=1` en el `instance_init` de tegra.xusb.
- Bits de lock de padctl/CAR/PMC solo donde el trace muestre una espera.

**Plan B si el dispositivo conectado en frío nunca se enumera:** conectarlo (`usb_attach`) cuando se active VBUS.

**Verificación:** `HVM_OTG_DEVICE=usb-kbd` en erista ams dir y mariko stock image:
- `usb_xhci_run`;
- attach a 480 Mb/s;
- slot direccionado y configurado;
- `info usb`;
- ninguna caída nueva.

La matriz por defecto no cambia.

### M25: modelo `usb-ax88772` (parche 0007) y account

**1. RE del driver AX88772 de `eth`**
- Secuencia de peticiones (RX_CTL/MFB, IPG, multicast, GPIO, EEPROM).
- Formato del PHY ID; registros MII y valores esperados.
- Cómo detecta el enlace: endpoint de interrupción o sondeo.
- Cabeceras RX/TX, relleno y alineación.
- Descriptores que comprueba.

**2. `hw/usb/dev-asix.c`** (`USB_ASIX`)
- **Descriptores FS/HS:** 0b95:7720, clase ff; EP 0x81 int (8 B), 0x02 bulk OUT 512, 0x83 bulk IN 512 (ajustado a lo
  que diga el RE).
- **Peticiones vendor:** 0x06–0x0a (MII), 0x0f/0x10 (RX_CTL), 0x12, 0x13/0x14 (MAC = `mac` de NICConf), 0x16,
  0x19, 0x1a/0x1b, 0x1e/0x1f, 0x20–0x22. Las desconocidas → STALL + evento.
- **PHY interno 0x10:** reset que se autolimpia, autonegociación inmediata a 100FD y enlace según el estado del NIC.
- **RX:** cola acotada con `can_receive`/`flush`; filtro según RX_CTL; tramas agregadas con cabecera
  `len|~len<<16`; NAK si está vacía y `usb_wakeup` al llegar una trama.
- **TX:** cabeceras reensambladas entre paquetes OUT.
- **Endpoint de interrupción** con el bit de enlace; `set_link` del monitor.

**3. `run.sh --eth ax88772`** (pasa a ser el valor por defecto en ams/stock)
- BM92T36 `otg`;
- `-netdev hubport` como sumidero hasta M26;
- `-device usb-ax88772,bus=usb-bus.2,port=1,netdev=…,mac=…`.

**4. `hvm_smoke`**
- Corto: AX88772 enumerado y configurado, y `eth` lo maneja (reset, PHY, MAC, RX_CTL start).
- `--long`: account ya no cae y construye `idgen:/context.bin`.
- Expectativas de caídas según `--eth`: `none` mantiene las de F3.

**5. Verificación:** celdas objetivo en los dos SoC, una celda `--eth none` por SoC y la matriz completa con el nuevo
valor por defecto.

### M26: `tools/hvm_net.py` (red aislada) y DHCP

**`serve`**
- Socket UNIX en `~/.horizonvm/run/net-<soc>.sock`, con un solo cliente.
- Termina al desconectarse QEMU.
- `umask 077`; patrón de `hvm_nbd`.
- **Nunca abre sockets AF_INET ni AF_PACKET.**

**Pila**

| Tráfico | Respuesta |
|---|---|
| ARP | Solo para la puerta de enlace y el DNS, nunca para la IP concedida |
| DHCP | DISCOVER/OFFER, REQUEST/ACK/NAK, INFORM, RELEASE; opciones 1, 3, 6, 51, 54, 58/59 |
| ICMP echo | Contesta |
| DNS | NXDOMAIN (A y AAAA) |
| TCP SYN | RST+ACK |
| Resto de UDP | Según la decisión menor 4 |
| IPv6 y otros | Se cuentan y se descartan |

- Log de eventos en `~/.horizonvm/logs/net-<soc>.log` (0600) y pcap opcional.
- **`run.sh`:** lanza `hvm_net` como a `hvm_nbd` y sustituye el hubport por
  `-netdev stream,server=off,addr.type=unix,...`.
- **Tests** (`TestHvmNet`, con un socketpair):
  - handshake DHCP (opciones y checksums);
  - ARP (respuesta para la puerta de enlace, silencio para la IP del cliente);
  - ICMP;
  - DNS;
  - SYN→RST;
  - tramas malformadas;
  - guarda que demuestra que no se crea ningún socket INET.
- **Smoke `--long`:** ACK DHCP a la MAC del adaptador y consulta `ctest.cdn.nintendo.net` respondida con NXDOMAIN.

### M27: frontera, docs y matriz final

- **Caracterizar con `--long`** en ams/stock y los dos SoC:
  - nifm tras el fallo del conntest;
  - account después de idgen;
  - el primer fallo nuevo en stock;
  - npns, bcat, nim, ssl.
- Ajustar `late_checks` y las expectativas.
- **Docs:** `docs/fase4.md` con el formato de fase3; en `CLAUDE.md`, que apunte a él; en `README.md`, `--eth` y
  `hvm_net`.
- **Matriz final:** 2 SoC × 4 perfiles × {image, dir}, más ams/stock `--long` y celdas `--eth none`. ams dir
  `--persist` solo con tu permiso, porque ahora escribe el contexto idgen en el save de account.
- `hvm_leakscan`.

## Riesgos principales y mitigación

| Riesgo | Mitigación |
|---|---|
| `usb` espera respuestas del firmware Falcon; si expira el tiempo, fatal y cascada en stock | Lista de comandos sacada del RE; `LOG_GUEST_ERROR`; primero ams |
| El xHCI de Horizon asume `CSZ=1` (contextos de 64 B), xECP propio o 9 puertos (HSIC) | Lo de xECP/puertos se resuelve en `xusb.c`. Si exige CSZ=1 hay que tocar `hcd-xhci.c`: **paro y te consulto** |
| Tormentas de IRQ GPIO | Semántica nueva solo en los pines conducidos |
| Diferencias del T214 (UPHY, otro firmware) | Mariko en cada hito |
| nifm necesita un perfil cableado o una petición de conexión | Observar primero; **consultar antes de crear saves** |
| `icount sleep=off` hace saltar timeouts de DHCP/USB | `hvm_net` responde de forma síncrona; el smoke exige que llegue el lease, no un plazo |
| Datos privados en los logs de red (nombres DNS, hostname DHCP) | Logs en `~/.horizonvm/logs`; ningún socket INET |
| `--persist` interrumpido corrompe saves | Sin `--persist` durante el arranque manual; `hvm_nbd.py sync` |

## Archivos

| Tipo | Archivos |
|---|---|
| Nuevos | Parches 0004–0007 (`gpio.c`, `hw/misc/bm92t36.c`, `xusb.c`/`tegrax1.c`, `hw/usb/dev-asix.c`), `tools/hvm_net.py`, `docs/fase4.md` |
| Modificados | `scripts/run.sh`, `tools/{hvm_log,hvm_smoke}.py`, `tools/tests/test_tools.py`, `README.md`, `CLAUDE.md` |

**Se reutilizan:**
- `hvm_nbd.py`: patrón de demonio del host y sockets en `run/`.
- `hw/misc/max77xpmic.c` + `tegra_init_pmic`: I2C con propiedades.
- `sdhci.c`: `dma_dev` + `tegra_mc_get_iommu_address_space`.
- `dev-network.c`: fontanería de NIC.
- `analyze`/`late_checks`/`expected_crashes` de `hvm_smoke`.

## Decisiones menores propuestas (confírmalas o cámbialas al aprobar)

1. **Orden:** primero el modelo AX88772 (M25) y después `hvm_net` (M26). account solo necesita la interfaz, y
   `hvm_net` no se puede probar de extremo a extremo sin el adaptador.
2. **MAC del adaptador fija por SoC**, administrada localmente: `02:48:56:4d:00:01` (erista) y `02:48:56:4d:00:02`
   (mariko). Es la MAC del adaptador, no identidad de la consola.
3. **Subred** tipo slirp: 10.0.2.0/24 (VM .15, puerta de enlace .2, DNS .3).
4. **Resto de UDP:** ICMP port unreachable, para que los clientes fallen rápido. El pcap queda desactivado por
   defecto (`--pcap`).
5. Si el RE muestra que el host XUSB arranca sin nada insertado, **M23 y M24 van en un solo commit** para que la
   matriz siga verde.
6. **BQ24193:** un modelo mínimo pequeño (no un parche del dummy), y solo si el RE muestra que se relee.

## Verificación de extremo a extremo

```
scripts/bootstrap.sh                                  # aplica 0004..0007 y recompila
python3 -m unittest discover -s tools/tests
tools/hvm_smoke.py --soc S --ini {empty,core,ams,stock} --nand {image,dir}     # S ∈ {erista, mariko}
tools/hvm_smoke.py --soc S --ini {ams,stock} --nand dir --long
tools/hvm_smoke.py --soc S --ini stock --nand dir --long --eth none            # frontera F3
tools/hvm_leakscan.py
```

**Criterio de éxito:**
- La matriz está verde.
- Con `ax88772`: host XUSB activo, AX88772 enumerado y manejado por `eth`, interfaz en nifm, lease DHCP en el log de
  `hvm_net`, account sin caída y sin cascada en stock.
- Con `none`: la frontera de F3 sin cambios.
- Ningún socket INET: nada sale del host.
