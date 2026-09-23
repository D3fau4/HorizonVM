/*
 * hvmtrace: QEMU TCG plugin logging AArch64 SMC calls/returns and MMIO accesses for HorizonVM.
 * usage: -plugin libhvmtrace.so,out=<file>[,mmio=off][,smc=off]
 * Secrets are redacted at the source: SE/SE2/PKA1 MMIO values, crypto SMC arguments/results.
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAX_VCPUS 8

static FILE *out;
static GMutex lock;
static GHashTable *smc_returns;   /* vaddr of the instruction after each smc seen at translation */
static bool log_mmio = true, log_smc = true;

typedef struct {
    struct qemu_plugin_register *x[8], *cpsr;
    uint64_t pending_ret, pending_id;
} VcpuState;
static VcpuState vcpus[MAX_VCPUS];

static const struct { uint64_t start, end; } redacted_mmio[] = {
    { 0x70012000, 0x70014000 },   /* SE   (keytable, crypto data) */
    { 0x70412000, 0x70414000 },   /* SE2  (Mariko) */
    { 0x70420000, 0x70430000 },   /* PKA1 (Mariko) */
};

/* Kernel-table SMCs whose arguments/results are not secret (NX kern_secure_monitor.cpp + PSCI). */
static bool smc_args_public(uint64_t id)
{
    switch (id) {
    case 0xC3000004: case 0xC3000005: case 0xC3000006: case 0xC3000007:
    case 0xC3000008: case 0xC3000409:
    case 0xC4000001: case 0x84000002: case 0xC4000003:
        return true;
    }
    return false;
}

static bool smc_results_public(uint64_t id)
{
    return smc_args_public(id) && id != 0xC3000005;   /* GenerateRandomBytes results are RNG output */
}

static uint64_t read_reg(struct qemu_plugin_register *r)
{
    g_autoptr(GByteArray) buf = g_byte_array_new();
    uint64_t v = 0;
    int n = r ? qemu_plugin_read_register(r, buf) : -1;
    if (n > 0) {
        memcpy(&v, buf->data, MIN((size_t)n, sizeof(v)));
    }
    return v;
}

static void log_regs(const char *tag, unsigned int cpu, uint64_t pc, uint64_t id,
                     int first, int last, bool public)
{
    VcpuState *s = &vcpus[cpu];
    GString *line = g_string_new(NULL);
    g_string_append_printf(line, "%s cpu=%u el=%" PRIu64 " pc=0x%" PRIx64 " id=0x%" PRIx64,
                           tag, cpu, (read_reg(s->cpsr) >> 2) & 3, pc, id);
    for (int i = first; i <= last; i++) {
        if (public) {
            g_string_append_printf(line, " x%d=0x%" PRIx64, i, read_reg(s->x[i]));
        } else {
            g_string_append_printf(line, " x%d=<redacted>", i);
        }
    }
    g_mutex_lock(&lock);
    fprintf(out, "%s\n", line->str);
    fflush(out);
    g_mutex_unlock(&lock);
    g_string_free(line, TRUE);
}

static void on_smc(unsigned int cpu, void *udata)
{
    if (cpu >= MAX_VCPUS || !vcpus[cpu].x[0]) {
        return;   /* not an AArch64 vCPU (BPMP/ADSP) */
    }
    VcpuState *s = &vcpus[cpu];
    uint64_t pc = (uint64_t)(uintptr_t)udata, id = read_reg(s->x[0]);
    log_regs("smc", cpu, pc, id, 1, 7, smc_args_public(id));
    s->pending_ret = pc + 4;
    s->pending_id = id;
}

static void on_smc_return(unsigned int cpu, void *udata)
{
    uint64_t pc = (uint64_t)(uintptr_t)udata;
    if (cpu >= MAX_VCPUS || !vcpus[cpu].x[0] || vcpus[cpu].pending_ret != pc) {
        return;
    }
    vcpus[cpu].pending_ret = 0;
    log_regs("smc_ret", cpu, pc, vcpus[cpu].pending_id, 0, 3, smc_results_public(vcpus[cpu].pending_id));
}

static void on_mem(unsigned int cpu, qemu_plugin_meminfo_t info, uint64_t vaddr, void *udata)
{
    struct qemu_plugin_hwaddr *hw = qemu_plugin_get_hwaddr(info, vaddr);
    if (!hw || !qemu_plugin_hwaddr_is_io(hw)) {
        return;
    }
    uint64_t pa = qemu_plugin_hwaddr_phys_addr(hw);
    unsigned size = 1u << qemu_plugin_mem_size_shift(info);
    bool secret = false;
    for (size_t i = 0; i < G_N_ELEMENTS(redacted_mmio); i++) {
        secret |= pa >= redacted_mmio[i].start && pa < redacted_mmio[i].end;
    }
    char val[24] = "<redacted>";
    if (!secret) {
        qemu_plugin_mem_value v = qemu_plugin_mem_get_value(info);
        uint64_t x = v.type == QEMU_PLUGIN_MEM_VALUE_U8 ? v.data.u8 :
                     v.type == QEMU_PLUGIN_MEM_VALUE_U16 ? v.data.u16 :
                     v.type == QEMU_PLUGIN_MEM_VALUE_U32 ? v.data.u32 : v.data.u64;
        snprintf(val, sizeof(val), "0x%" PRIx64, x);
    }
    g_mutex_lock(&lock);
    fprintf(out, "mmio cpu=%u pc=0x%" PRIx64 " %c addr=0x%" PRIx64 " size=%u val=%s\n", cpu,
            (uint64_t)(uintptr_t)udata, qemu_plugin_mem_is_store(info) ? 'W' : 'R', pa, size, val);
    g_mutex_unlock(&lock);
}

static void on_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t va = qemu_plugin_insn_vaddr(insn);
        void *udata = (void *)(uintptr_t)va;
        if (log_mmio) {
            qemu_plugin_register_vcpu_mem_cb(insn, on_mem, QEMU_PLUGIN_CB_NO_REGS, QEMU_PLUGIN_MEM_RW, udata);
        }
        if (!log_smc) {
            continue;
        }
        uint32_t op = 0;
        if (qemu_plugin_insn_size(insn) == 4) {
            qemu_plugin_insn_data(insn, &op, sizeof(op));
        }
        g_mutex_lock(&lock);
        if ((op & 0xFFE0001F) == 0xD4000003) {   /* SMC #imm16 */
            g_hash_table_add(smc_returns, (gpointer)(uintptr_t)(va + 4));
            g_mutex_unlock(&lock);
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_smc, QEMU_PLUGIN_CB_R_REGS, udata);
            continue;
        }
        bool is_ret = g_hash_table_contains(smc_returns, (gpointer)(uintptr_t)va);
        g_mutex_unlock(&lock);
        if (is_ret) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_smc_return, QEMU_PLUGIN_CB_R_REGS, udata);
        }
    }
}

static void on_vcpu_init(qemu_plugin_id_t id, unsigned int cpu)
{
    if (cpu >= MAX_VCPUS) {
        return;
    }
    g_autoptr(GArray) regs = qemu_plugin_get_registers();
    for (guint i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *d = &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        if (d->name[0] == 'x' && d->name[1] >= '0' && d->name[1] <= '7' && d->name[2] == '\0') {
            vcpus[cpu].x[d->name[1] - '0'] = d->handle;
        } else if (!strcmp(d->name, "cpsr")) {
            vcpus[cpu].cpsr = d->handle;
        }
    }
}

static void on_plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_mutex_lock(&lock);
    fflush(out);
    g_mutex_unlock(&lock);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{
    const char *path = NULL;
    for (int i = 0; i < argc; i++) {
        g_auto(GStrv) kv = g_strsplit(argv[i], "=", 2);
        if (!kv[1]) {
            continue;
        } else if (!strcmp(kv[0], "out")) {
            path = argv[i] + 4;
        } else if (!strcmp(kv[0], "mmio")) {
            log_mmio = strcmp(kv[1], "off") != 0;
        } else if (!strcmp(kv[0], "smc")) {
            log_smc = strcmp(kv[1], "off") != 0;
        }
    }
    if (!path || !(out = fopen(path, "w"))) {
        fprintf(stderr, "hvmtrace: need a writable out=<file>\n");
        return -1;
    }
    setvbuf(out, NULL, _IOFBF, 1 << 20);
    smc_returns = g_hash_table_new(g_direct_hash, g_direct_equal);
    qemu_plugin_register_vcpu_init_cb(id, on_vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_trans);
    qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
    return 0;
}
