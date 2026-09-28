# Fase 3: estado (2026-09-28)

Rama `fase3` sobre `main` (459d860). Hechos: M17 de13883, M18 43eea0d, M19 2b93016, fix de fuga b19adbd, M20 d332a00.
Smoke (`tools/hvm_smoke.py`) verde en erista y mariko × {empty, core, ams, stock} × {image, dir} + ams/dir/--persist.

## Frontera actual
- ams: sin caídas; boot2 desde stratosphere.romfs lanza toda su lista (hasta memlet). `es` espera `ssl:s`
  (ssl no llega a registrarlo); `nvservices` gira en bucle (GPU no emulada) y ocupa el core 3.
- stock: boot2 oficial lanza su lista; cae `bluetooth` (010000000000000b, svc::Break).
- Pendiente de emulación: EMC queda a 19,2 MHz (estado de bootloader, no bloquea); los registros del PMIC
  (max77xpmic) no se reinician en un reset de QEMU.

## Pendiente
- M21 (ams): caracterizar la lista post-SD (qué registra cada módulo, dónde se para), investigar `ssl:s`,
  comprobación `--maintenance` (boot2 elige la lista de mantenimiento), escaneo de fugas que excluya
  `~/.horizonvm/sd/<soc>/` (ams_mitm guarda ahí BISKEYS.bin).
- M22 (stock): caracterizar el boot2 oficial, investigar la caída de `bluetooth`, fijar `smoke --ini stock`,
  cerrar la matriz final y hacer merge `--no-ff` de `fase3` a `main` (solo si el usuario lo pide).

## Herramientas de depuración
- `HVM_TRACE_ARGS=watch_pid=N,watch=off1:off2` + `run.sh --trace`: vuelca x0–x30 del proceso N en offsets de
  código (`pc & 0x1FFFFF`). Los PID son deterministas. Nunca sobre procesos con claves (spl, FS…).
- Las peticiones a `sm` llevan `bt=` (cadena de retorno). Binarios de Nintendo: descomprimir NSO/KIP con lz4/BLZ
  en `~/.horizonvm/tmp/re` y abrir en IDA; nunca en el repo.
- GDB sobre exosphere: `set print frame-arguments none` (los argumentos de sus funciones crypto son claves).

## Normas
No parchear Atmosphère; parches neutros de tegra_qemu solo si hace falta; un commit `Mx:` por hito verificado,
sin push; secretos solo en `~/.horizonvm` (0700/0600); nunca imprimir ni versionar claves; el firmware de
Nintendo nunca entra en el repo; decisiones de diseño, consultar al usuario.

## Plan aprobado

### HorizonVM, fase 3: ams_mitm, SD sintética, desbloqueo de pcv y CAL0 generado

## Contexto

F2 está en `main` (459d860, M8..M16). Hay dos fronteras:

- **ams** se queda en `boot` → `InitializeForBoot` con un bucle `ConnectToNamedPort("bpc:ams")` (`LS/ams/ams_bpc.os.horizon.c:24-33`). Ese puerto solo lo crea `ams_mitm`, que no se compila ni va en el INI1 (`scripts/build.sh:10,31`).
- **stock**: `boot` ejecuta su `Main` completo (I2C, GPIO, PWM, pantalla) y sale; boot2 lanza psc/settings/usb/pcie/Bus/pcv/htc.stub/omm. Luego todo se encadena detrás de **pcv**:
  - el hilo de init de pcv hace `GetServiceHandle("fatal:u")` y se queda esperando;
  - clkrst no responde a `OpenSession`, así que FS, Bus y pcie se bloquean;
  - Loader queda esperando a FS, pm a Loader y boot2 a pm.
  - Justo antes, pcv lee `CAR SPARE_REG0` (0x6000655C) y varios fuses de calibración (0x7000F914/918/930/934/940/A28), y todos valen 0. Probablemente va a lanzar un fatal.

Como pcv es de Nintendo en los dos perfiles, este bloqueo afecta también a ams: `ams_mitm` espera `pcv`, `gpio`, `pinmux` y `psc:m` antes de abrir la SD (`cfg_sd_card.board.nintendo_nx.inc:23-53`).

**Objetivo de F3:**
- en **ams**: ams_mitm activo, SD montada, boot2 cargado desde `stratosphere.romfs` y la lista post-SD lanzada;
- en **stock**: boot2 pasa de omm;
- un **CAL0 generado**;
- las dos fronteras nuevas caracterizadas.

Todo en Erista y Mariko.

**Decisiones del usuario:**
- Se cubren las dos rutas, ams y stock.
- package3 y stratosphere.romfs salen de **`make dist` sin modificar**, en release oficial. Los KIPs del INI1 siguen en debug.
- SD con **imagen y carpeta NBD** (write-back), **8 GiB** por defecto y `--size`.
- Pantalla headless por defecto, con `--display` para verla.
- Botones de volumen sueltos por defecto, con `--maintenance`.
- pcv: **diagnóstico con IDA** y corrección en los datos del host (fuses en mkfuses; parche neutro de tegra_qemu solo si el valor lo pone el bootloader o el hardware).
- HardwareType: se mantienen Icosa y Iowa.
- CAL0: **generado** (`mkcal0.py`), importando del PRODINFO real del usuario **solo la calibración no identificativa**.

**Normas que siguen en vigor:**
- no parchear Atmosphère;
- un commit `Mx:` por hito verificado en la rama `fase3`, sin push;
- documentar lo justo;
- secretos solo en `~/.horizonvm` (0700/0600) y ningún valor de clave en logs ni salidas;
- no mezclar identidad real y sintética;
- el firmware de Nintendo nunca entra en el repo.

**Abreviaturas:** `AMS/`, `LS/` (libstratosphere/source), `ST/` (stratosphere), `TQ/` (tegra_qemu/hw/arm/tegra2).

## Hallazgos que fijan el diseño

**ams_mitm**
- Es un KIP de package3 y va en el INI1 detrás de `spl` (`AMS/fusee/build_package3.py:23`).
- `bpc:ams` es un *named port* del kernel y se crea de inmediato (`ST/ams_mitm/source/bpc_mitm/bpc_ams_module.cpp:37-42`).
- El primer `SetRebootPayload` de boot dispara la inicialización (`bpc_ams_service.cpp:36-45`):
  - lee PRODINFO con `R_ABORT_UNLESS`;
  - abre la SD con `R_ABORT_UNLESS(fsOpenSdCardFileSystem)`: **sin SD, aborta**;
  - escribe `/atmosphere/automatic_backups/<SN>_PRODINFO.bin` y `<ref>_BISKEYS.bin`, este último **con las claves BIS sintéticas**;
  - abre con abort `/atmosphere/package3` y `/atmosphere/stratosphere.romfs` (`amsmitm_initialization.cpp:90-145`).

**Implicación para la SD:** debe ser **por SoC y 0700** (`~/.horizonvm/sd/<soc>/`), y el escaneo de fugas debe excluir ese árbol.

**pm/boot2 de Atmosphère** (`LS/boot2/boot2_api.board.nintendo_nx.cpp:337-465`)
1. Espera el mitm de `fsp-srv`.
2. Lanza psc, pcie, bus, settings, pcv y usb desde la NAND.
3. Espera la SD y el mitm de `set:sys`, y en Erista también el mitm de `bpc`.
4. Lanza **boot2 (0x…08) con `StorageId::None`**, es decir, desde el romfs de la SD.
5. Después vienen dmnt/tma, lm, la lista normal (omm … ngct) o la de mantenimiento, memlet y los programas de la SD con `boot2.flag`.

Loader sustituye el código en este orden: SD `/atmosphere/contents/<id>/exefs.nsp`, luego `stratosphere.romfs`, luego la NAND (`ldr` `fs_code.cpp:155-163`).

**SD en tegra_qemu**
- SDMMC1 ya está conectado a `-drive if=sd,index=0` (`TQ/tegrax1.c:936`).
- El *card detect* PZ1 lee 0, que significa insertada.
- No hay UHS: se queda en 3,3 V.
- El LDO2 del PMIC `max77xpmic` responde con POK.
- El FS de `BootImagePackage` es la variante sin exFAT, así que la SD va en **FAT32 dentro de un MBR** (tipo 0x0C).

**Botones:** GPIO_IN vale 0 en el reset, así que VolUp (X6) y VolDn (X7) leen "pulsados" y boot2 forzaría el mantenimiento (`boot2_api…cpp:214-224`). Se sueltan con `-global tegra.gpio.reset-value-bank5-port3=0xC0` (README de tegra_qemu).

**Pantalla:** el DC emulado hace *scanout* a una consola de QEMU y su vblank avanza el syncpt 9. Por eso el bucle de `FinalizeDisplay` termina (stock ya lo demuestra).

**CAL0 del usuario** (`~/Descargas/INVALID_PRODINFO_797EED32.bin`)
- Revisado solo en su estructura: CAL0 v7, `body_size` 0x7FC0, *hash* del cuerpo válido.
- **Todavía conserva datos reales:** el serial (14 B), el certificado ECC-B233 con CRC válido y las raíces amiibo.
- Los bloques y sus offsets están en `ST/ams_mitm/source/amsmitm_prodinfo_utils.cpp:153-162`; los accesores, en `LS/cal/`.

## Hitos (rama `fase3` desde `main`)

Cada hito amplía `smoke` y mantiene verde la matriz anterior en erista y mariko.

### M17: `make dist` y SD sintética (imagen + carpeta NBD)

**`scripts/build.sh`**
- Añade `ams_mitm` a `MODULES` (debug, para el INI1).
- Con `HVM_DIST=1`, o si no existe `AMS/out/…/atmosphere/package3`, ejecuta `make -C AMS dist` sin modificar.
- Si faltan dependencias de troposphere u otras, **te consulto** antes de instalar paquetes con `dkp-pacman`.

**`tools/mksd.py`** (nuevo, siguiendo el patrón de `mknand.py`)
- `--soc S --dist DIR`: rellena `~/.horizonvm/sd/<soc>/dir/` con el `atmosphere/` de la dist (package3, stratosphere.romfs, config de ejemplo). No copia `bootloader/` ni `switch/`, que la VM no necesita, salvo que prefieras la dist completa.
- `--image [--size 8G]`: MBR con una partición tipo 0x0C alineada a 4 MiB y FAT32 con clústeres de 32 KiB. Se construye con `mkfs.fat` + `mcopy` sobre un fichero *sparse*.
- `--verify`: `fsck.fat` y hashes de los ficheros.

**`tools/hvm_nbd.py`**
- Se generaliza el disco a una lista de regiones:
  - `VirtualEmmc` (sin cambios);
  - `VirtualSd` nuevo: MBR + `FatSynth` sin clave (`_region_read` ya se salta XTS con `key=None`).
- `Overlay` y `reconcile` se parametrizan por disco (tamaño, LBA y particiones) en lugar de `nand.IMAGE_SIZE`/`PARTITIONS`.
- CLI: `serve|sync|export --disk emmc|sd`.

**`scripts/run.sh`**
- `--sd image|dir|none`. Por defecto sigue a `--nand`, y es `none` en los perfiles empty/core.
- Añade `-drive if=sd,index=0,...`, con un segundo servidor NBD y su socket.
- `--persist` se aplica a los dos discos.

**Tests**
- MBR y FAT de `VirtualSd` idénticos a los de la imagen, fuera de los clústeres libres.
- `fsck.fat` limpio.
- Ida y vuelta del write-back en la SD.
- Los tests del eMMC siguen verdes.

**Smoke:** la matriz actual sin cambios con la SD conectada (nadie la lee todavía).

### M18: ams_mitm en el INI1, botones y `--display`

- **Perfil `ams`:** `loader ncm pm sm boot spl ams_mitm` + FS, en el orden de fusee.
- **`run.sh`:** `-global tegra.gpio.reset-value-bank5-port3=0xC0` por defecto; `--maintenance` lo deja a 0; `--display` cambia `-display none` por la ventana de QEMU (gtk o sdl, según lo compilado).
- **`hvmtrace` y `hvm_log`:**
  - nombre de proceso `ams_mitm`;
  - `bpc:ams` como *named port* (ya se decodifica `ManageNamedPort`);
  - allowlist de MMIO de `ams_mitm`, si toca alguno.
- **Qué se espera:**
  - boot pasa `InitializeForBoot` y ejecuta `Main` como en stock (I2C, pantalla, batería, `CheckClock`) hasta `NotifyBootFinished`;
  - pm lanza psc…pcv;
  - ams_mitm lee PRODINFO y queda esperando la SD detrás de pcv, que es la frontera compartida con stock.
- **Smoke `ams`:**
  - bpc:ams creado;
  - las SMC `SetBootReason` y `SetConfig` de boot;
  - `NotifyBootFinished` hecho;
  - los procesos del boot2 de pm vivos;
  - cero violaciones.

### M19: pcv deja de pedir `fatal:u` (IDA + datos del host)

1. Con IDA (`ida-pro-mcp`), abrir el NSO de pcv extraído del NCA de la NAND:
   - en la carpeta de trabajo privada `~/.horizonvm/tmp`, nunca en el repo;
   - si hace falta, se extrae con hactool o LibHac.
2. Seguir el hilo de init hasta la llamada a fatal, cerca de `pc 0x…a43f618` menos el *slide*: ver qué registro o fuse compara y qué valor espera.
3. Corregir la causa con este orden de preferencia:
   - **fuse** (speedo, IDDQ, calibración): se escribe en `mkfuses.py` un valor retail típico, documentado con su origen y validado con `static_assert` contra `fuse_registers.hpp`, como en M10;
   - **registro que inicializa el bootloader** (fusee o warmboot), p. ej. `SPARE_REG0` con el divisor de CLK_M (`fusee_secure_initialize.cpp:202`): patch neutro `patches/tegra_qemu/0003-…` que modifica el valor de reset del registro para que coincida con el estado posterior a fusee. La alternativa, un `-device loader` que escriba el valor, se valorará si es más limpia;
   - si es otra cosa (p. ej. hardware sin emular), **paro y te consulto**.
4. **Verificación:**
   - en stock, clkrst responde, FS/Loader/pm se desbloquean y boot2 lanza el programa siguiente a omm;
   - en ams, `ams_mitm` supera `WaitSdCardInitialized`;
   - `smoke --ini stock` se amplía.

### M20: CAL0 generado (`tools/mkcal0.py`)

**Referencia**
- Tu fichero se copia a `~/.horizonvm/ref/prodinfo-ref.bin` (0600). Te recomendaré borrar la copia de `Descargas`; no la borro yo.
- La referencia es opcional: sin ella, se generan valores retail por defecto.

**Generación:** CAL0 v7 con la cabecera (CRC16 + SHA-256 del cuerpo) y todos los bloques con CRC/SHA correctos.

**Identidad 100 % sintética**, derivada del ECID de la VM:
- serial alfanumérico de 14 caracteres con prefijo retail;
- MAC de WLAN y BD_ADDR con el bit de *locally administered*;
- lote de batería;
- certificados ECC-B233 y RSA-2048 con estructura válida, firma nula y ID de dispositivo sintético;
- claves de dispositivo, SSL y amiibo a cero con CRC válido, como el *Blank* de ams_mitm.

**Importado de la referencia, lista blanca por offset:** ConfigurationId1, códigos de país WLAN, calibración de acelerómetro y giroscopio, versión y vendor de la batería, colores de carcasa, región, modelo del producto, vendor del LCD y mapeo de brillo, calibración de altavoz y de la pantalla táctil. **La lista exacta, con sus offsets, te la enseñaré antes de implementarla.**

**Uso:** `mknand.py` usa `mkcal0` en lugar de `build_blank_cal0`, con `--cal0 blank` para volver al comportamiento anterior. El `PRODINFO.bin` del árbol se regenera.

**Tests**
- Estructura: todos los CRC y SHA válidos; `check_cal0`.
- **Aislamiento:** solo se copian bytes de la referencia dentro de la lista blanca, y ningún byte de las zonas identificativas coincide con ella. Es un test local que se salta sin la referencia.

**Funcional:**
- ams_mitm guarda `<SN>_PRODINFO.bin` y no `BLANK_`/`INVALID_`;
- boot lee el vendor de la batería sin recurrir al valor por defecto;
- settings obtiene el serial.

### M21: ams, SD montada y boot2 desde `stratosphere.romfs`

**Qué se espera ver:**
- ams_mitm crea `automatic_backups` en la SD (con `--persist`, en la carpeta);
- `set`/`set:sys` como mitm, y `bpc` como mitm en Erista;
- pm lanza boot2 desde la SD, loader lo toma del romfs;
- boot2 lanza dmnt/tma, lm y la lista normal, además de memlet.

**Caracterización, igual que en M14:** qué registra cada módulo y dónde se detiene cada uno (se esperan nvservices/vi por la GPU sin emular, wlan/bt, etc.). El estado reproducible queda como expectativa de `smoke --ini ams`.

**`--maintenance`:** una comprobación de que boot2 elige la lista de mantenimiento.

**Escaneo de fugas:** excluye `~/.horizonvm/sd/<soc>/` y comprueba que `BISKEYS.bin` no sale de ahí.

### M22: stock, boot2 completo, y cierre de fronteras

- Con pcv arreglado, se caracteriza el avance del boot2 oficial (ProdBoot) sobre la misma NAND y el nuevo CAL0.
- Se documenta en el hito la frontera de cada módulo, sin parchear nada, y se fija `smoke --ini stock`.
- Se cierra la matriz final: SoC × {empty, core, ams, stock} × NAND {image, dir}. La SD sigue al backend de la NAND.

## Archivos

| Tipo | Archivos |
|---|---|
| Nuevos | `tools/mksd.py`, `tools/mkcal0.py`; posible `patches/tegra_qemu/0003-*.patch` (M19) |
| Modificados | `scripts/{build,run}.sh`, `tools/{hvm_nbd,hvm_nand,mknand,mkfuses,hvm_log,hvm_smoke}.py`, `plugins/hvmtrace.c` (si hace falta), `tools/tests/test_tools.py`, `README.md` (solo comandos nuevos) |

**Se reutilizan:**
- `FatSynth`, `Overlay`, `reconcile` y `serve` de `hvm_nbd.py`;
- `make_fat`/`extents`/`verify` de `mknand.py`;
- `crc16`/`check_cal0` de `hvm_nand.py`;
- el patrón `static_assert` de `mkfuses`;
- `analyze`, `stock_checks`/`ams_checks` y el muestreo de `hvm_smoke.py`.

## Decisiones menores propuestas (confírmalas o cámbialas al aprobar)

1. La SD es **por SoC** (`~/.horizonvm/sd/<soc>/`), porque ams_mitm escribe en ella las claves BIS de ese SoC.
2. El backend de la SD sigue al de la NAND en la matriz de smoke, para no multiplicarla.
3. A la SD se copia solo `atmosphere/` de la dist (sin `bootloader/`, `switch/` ni `hbmenu.nro`).
4. `mknand` usa por defecto el CAL0 generado, con `--cal0 blank` como opción.
5. La numeración de hitos continúa (M17…M22).

## Verificación de extremo a extremo

```
HVM_FW=<FW> HVM_DIST=1 scripts/build.sh
tools/mkfuses.py --soc S && tools/hvm_keys.py --soc S --prod-keys <FW>/prod.keys --derive-bis
tools/mkcal0.py --soc S [--ref ~/.horizonvm/ref/prodinfo-ref.bin]
tools/mknand.py --soc S --fw <FW> && tools/mknand.py --soc S --image
tools/mksd.py --soc S --dist AMS/out/.../ && tools/mksd.py --soc S --image
python3 -m unittest discover -s tools/tests
tools/hvm_smoke.py --soc S --ini {empty,core,ams,stock} --nand {image,dir}   # S ∈ {erista, mariko}
scripts/run.sh --soc S --ini ams --nand dir --persist --display              # vista manual del splash
```

**Criterio de éxito:**
- La matriz está verde.
- En **ams**: bpc:ams creado, boot completo, SD montada, `automatic_backups` en la carpeta, boot2 cargado desde el romfs y la lista post-SD caracterizada.
- En **stock**: pcv sin `fatal:u` y boot2 más allá de omm.
- El CAL0 generado es válido y pasa el test de aislamiento.
- Ningún byte de clave fuera de `~/.horizonvm`.
