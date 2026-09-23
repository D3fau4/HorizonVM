/*
 * hvmtrace: QEMU TCG plugin logging AArch64 SMC calls/returns, EL0 SVCs and MMIO accesses for HorizonVM.
 * usage: -plugin libhvmtrace.so,out=<file>[,mmio=off][,smc=off][,svc=off]
 * Secrets are redacted at the source: SE/SE2/PKA1 MMIO values, crypto SMC arguments/results, and no IPC
 * message is dumped except requests to sm (service names).
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAX_VCPUS 8

/* Horizon SVC ids (svc_definition_macro.hpp). */
#define SVC_CLOSE_HANDLE                    0x16
#define SVC_CONNECT_TO_NAMED_PORT           0x1F
#define SVC_SEND_SYNC_REQUEST               0x21
#define SVC_SEND_SYNC_REQUEST_WITH_USER_BUF 0x22
#define SVC_MANAGE_NAMED_PORT               0x71
#define SM_MSG_LOG_SIZE                     0x40

static FILE *out;
static GMutex lock;
static GHashTable *smc_returns;   /* vaddr of the instruction after each smc seen at translation */
static GHashTable *svc_returns;   /* same for EL0 svc */
static GHashTable *svc_pending;   /* thread key -> SvcCall, for calls that have not returned yet */
static GHashTable *sm_sessions;   /* (pid, handle) of sessions to the "sm:" port */
static bool log_mmio = true, log_smc = true, log_svc = true;

typedef struct {
    struct qemu_plugin_register *x[8], *cpsr, *contextidr, *tpidrro;
    uint64_t pending_ret, pending_id, pending_imm;
} VcpuState;
static VcpuState vcpus[MAX_VCPUS];

typedef struct {
    uint64_t ret_pc, id;
    bool connect_sm;   /* ConnectToNamedPort("sm:"): remember the returned handle */
} SvcCall;

static const struct { uint64_t start, end; } redacted_mmio[] = {
    { 0x70012000, 0x70014000 },   /* SE   (keytable, crypto data) */
    { 0x70412000, 0x70414000 },   /* SE2  (Mariko) */
    { 0x70420000, 0x70430000 },   /* PKA1 (Mariko) */
};

/*
 * exosphere picks the handler table by the smc immediate (secmon_smc_handler.cpp): #1 is the kernel table,
 * #0 the user one, and both reuse ids (e.g. 0xC3000006-08 are ShowError/SetKernelCarveoutRegion/
 * ReadWriteRegister for the kernel but GenerateRandomBytes/GenerateAesKek/LoadAesKey for users).
 */
static bool smc_args_public(uint64_t imm, uint64_t id)
{
    if (imm == 1) {   /* NX kern_secure_monitor.cpp + PSCI */
        switch (id) {
        case 0xC3000004: case 0xC3000005: case 0xC3000006: case 0xC3000007:
        case 0xC3000008: case 0xC3000409:
        case 0xC4000001: case 0x84000002: case 0xC4000003:
            return true;
        }
    } else if (imm == 0) {
        return id == 0xC3000002 || id == 0xC3000401;   /* GetConfig / SetConfig */
    }
    return false;
}

static bool smc_results_public(uint64_t imm, uint64_t id)
{
    /* Kernel GenerateRandomBytes results are RNG output. */
    return smc_args_public(imm, id) && !(imm == 1 && id == 0xC3000005);
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

static void emit(GString *line, bool flush)
{
    g_mutex_lock(&lock);
    fprintf(out, "%s\n", line->str);
    if (flush) {
        fflush(out);
    }
    g_mutex_unlock(&lock);
    g_string_free(line, TRUE);
}

static void append_regs(GString *line, VcpuState *s, int first, int last, bool public)
{
    for (int i = first; i <= last; i++) {
        if (public) {
            g_string_append_printf(line, " x%d=0x%" PRIx64, i, read_reg(s->x[i]));
        } else {
            g_string_append_printf(line, " x%d=<redacted>", i);
        }
    }
}

static void log_smc_regs(const char *tag, unsigned int cpu, uint64_t pc, uint64_t imm, uint64_t id,
                         int first, int last, bool public)
{
    VcpuState *s = &vcpus[cpu];
    GString *line = g_string_new(NULL);
    g_string_append_printf(line, "%s cpu=%u el=%" PRIu64 " pc=0x%" PRIx64 " imm=%" PRIu64 " id=0x%" PRIx64,
                           tag, cpu, (read_reg(s->cpsr) >> 2) & 3, pc, imm, id);
    append_regs(line, s, first, last, public);
    emit(line, true);
}

static bool is_aarch64_vcpu(unsigned int cpu)
{
    return cpu < MAX_VCPUS && vcpus[cpu].x[0];   /* not the BPMP/ADSP */
}

static void on_smc(unsigned int cpu, void *udata)
{
    if (!is_aarch64_vcpu(cpu)) {
        return;
    }
    VcpuState *s = &vcpus[cpu];
    uint64_t pc = (uint64_t)(uintptr_t)udata, id = read_reg(s->x[0]);
    uint32_t op = 0;
    g_autoptr(GByteArray) insn = g_byte_array_new();
    if (qemu_plugin_read_memory_vaddr(pc, insn, 4) && insn->len == 4) {
        memcpy(&op, insn->data, 4);
    }
    uint64_t imm = (op >> 5) & 0xFFFF;
    log_smc_regs("smc", cpu, pc, imm, id, 1, 7, smc_args_public(imm, id));
    s->pending_ret = pc + 4;
    s->pending_id = id;
    s->pending_imm = imm;
}

static void on_smc_return(unsigned int cpu, void *udata)
{
    uint64_t pc = (uint64_t)(uintptr_t)udata;
    if (!is_aarch64_vcpu(cpu) || vcpus[cpu].pending_ret != pc) {
        return;
    }
    VcpuState *s = &vcpus[cpu];
    s->pending_ret = 0;
    log_smc_regs("smc_ret", cpu, pc, s->pending_imm, s->pending_id, 0, 3,
                 smc_results_public(s->pending_imm, s->pending_id));
}

/* Threads are identified by process id (CONTEXTIDR_EL1, cpu::SwitchProcess) and their TLS (TPIDRRO_EL0). */
static gpointer thread_key(uint64_t pid, uint64_t tls)
{
    return (gpointer)(uintptr_t)((pid << 40) ^ tls);
}

static gpointer handle_key(uint64_t pid, uint64_t handle)
{
    return (gpointer)(uintptr_t)((pid << 32) | (handle & 0xFFFFFFFF));
}

static void append_user_string(GString *line, const char *field, uint64_t va, size_t max)
{
    g_autoptr(GByteArray) buf = g_byte_array_new();
    g_string_append_printf(line, " %s=", field);
    if (!qemu_plugin_read_memory_vaddr(va, buf, max)) {
        g_string_append(line, "?");
        return;
    }
    for (guint i = 0; i < buf->len && buf->data[i]; i++) {
        char c = buf->data[i];
        g_string_append_c(line, (c > ' ' && c < 0x7F) ? c : '?');
    }
}

static void append_user_hex(GString *line, const char *field, uint64_t va, size_t len)
{
    g_autoptr(GByteArray) buf = g_byte_array_new();
    g_string_append_printf(line, " %s=", field);
    if (!qemu_plugin_read_memory_vaddr(va, buf, len)) {
        g_string_append(line, "?");
        return;
    }
    for (guint i = 0; i < buf->len; i++) {
        g_string_append_printf(line, "%02x", buf->data[i]);
    }
}

static void on_svc(unsigned int cpu, void *udata)
{
    if (!is_aarch64_vcpu(cpu)) {
        return;
    }
    VcpuState *s = &vcpus[cpu];
    if (((read_reg(s->cpsr) >> 2) & 3) != 0) {
        return;
    }
    uint64_t pc = (uint64_t)(uintptr_t)udata;
    uint32_t op = 0;
    g_autoptr(GByteArray) insn = g_byte_array_new();
    if (qemu_plugin_read_memory_vaddr(pc, insn, 4) && insn->len == 4) {
        memcpy(&op, insn->data, 4);
    }
    uint64_t id = (op >> 5) & 0xFFFF;
    uint64_t pid = read_reg(s->contextidr) & 0xFFFFFFFF, tls = read_reg(s->tpidrro);
    uint64_t x0 = read_reg(s->x[0]), x1 = read_reg(s->x[1]), x2 = read_reg(s->x[2]);

    GString *line = g_string_new(NULL);
    g_string_append_printf(line, "svc cpu=%u pid=%" PRIu64 " tls=0x%" PRIx64 " pc=0x%" PRIx64 " id=0x%" PRIx64,
                           cpu, pid, tls, pc, id);
    append_regs(line, s, 0, 3, true);

    SvcCall *call = g_new0(SvcCall, 1);
    call->ret_pc = pc + 4;
    call->id = id;
    g_mutex_lock(&lock);
    bool sm_session = false;
    if (id == SVC_SEND_SYNC_REQUEST) {
        sm_session = g_hash_table_contains(sm_sessions, handle_key(pid, x0));
    } else if (id == SVC_SEND_SYNC_REQUEST_WITH_USER_BUF) {
        sm_session = g_hash_table_contains(sm_sessions, handle_key(pid, x2));
    } else if (id == SVC_CLOSE_HANDLE) {
        g_hash_table_remove(sm_sessions, handle_key(pid, x0));
    }
    g_mutex_unlock(&lock);

    if (id == SVC_CONNECT_TO_NAMED_PORT || id == SVC_MANAGE_NAMED_PORT) {
        g_autoptr(GByteArray) name = g_byte_array_new();
        append_user_string(line, "name", x1, 12);
        call->connect_sm = id == SVC_CONNECT_TO_NAMED_PORT && qemu_plugin_read_memory_vaddr(x1, name, 4) &&
                           name->len == 4 && !memcmp(name->data, "sm:\0", 4);
    } else if (sm_session) {
        /* Only sm requests are dumped: they carry service names, never key material. */
        append_user_hex(line, "sm_msg", id == SVC_SEND_SYNC_REQUEST ? tls : x0, SM_MSG_LOG_SIZE);
    }
    emit(line, false);

    g_mutex_lock(&lock);
    g_hash_table_replace(svc_pending, thread_key(pid, tls), call);
    g_mutex_unlock(&lock);
}

static void on_svc_return(unsigned int cpu, void *udata)
{
    if (!is_aarch64_vcpu(cpu)) {
        return;
    }
    VcpuState *s = &vcpus[cpu];
    uint64_t pc = (uint64_t)(uintptr_t)udata;
    uint64_t pid = read_reg(s->contextidr) & 0xFFFFFFFF, tls = read_reg(s->tpidrro);
    gpointer key = thread_key(pid, tls);

    g_mutex_lock(&lock);
    SvcCall *call = g_hash_table_lookup(svc_pending, key);
    if (!call || call->ret_pc != pc) {
        g_mutex_unlock(&lock);
        return;
    }
    uint64_t id = call->id;
    bool connect_sm = call->connect_sm;
    g_hash_table_remove(svc_pending, key);
    uint64_t x0 = read_reg(s->x[0]), x1 = read_reg(s->x[1]);
    if (connect_sm && x0 == 0) {
        g_hash_table_add(sm_sessions, handle_key(pid, x1));
    }
    g_mutex_unlock(&lock);

    GString *line = g_string_new(NULL);
    g_string_append_printf(line, "svc_ret cpu=%u pid=%" PRIu64 " tls=0x%" PRIx64 " pc=0x%" PRIx64 " id=0x%" PRIx64,
                           cpu, pid, tls, pc, id);
    append_regs(line, s, 0, 3, true);
    emit(line, false);
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
        uint32_t op = 0;
        if (qemu_plugin_insn_size(insn) == 4) {
            qemu_plugin_insn_data(insn, &op, sizeof(op));
        }
        g_mutex_lock(&lock);
        if (log_smc && (op & 0xFFE0001F) == 0xD4000003) {          /* SMC #imm16 */
            g_hash_table_add(smc_returns, (gpointer)(uintptr_t)(va + 4));
            g_mutex_unlock(&lock);
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_smc, QEMU_PLUGIN_CB_R_REGS, udata);
            continue;
        }
        if (log_svc && (op & 0xFFE0001F) == 0xD4000001) {          /* SVC #imm16 */
            g_hash_table_add(svc_returns, (gpointer)(uintptr_t)(va + 4));
            g_mutex_unlock(&lock);
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_svc, QEMU_PLUGIN_CB_R_REGS, udata);
            continue;
        }
        bool smc_ret = g_hash_table_contains(smc_returns, (gpointer)(uintptr_t)va);
        bool svc_ret = g_hash_table_contains(svc_returns, (gpointer)(uintptr_t)va);
        g_mutex_unlock(&lock);
        if (smc_ret) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_smc_return, QEMU_PLUGIN_CB_R_REGS, udata);
        }
        if (svc_ret) {
            qemu_plugin_register_vcpu_insn_exec_cb(insn, on_svc_return, QEMU_PLUGIN_CB_R_REGS, udata);
        }
    }
}

static void on_vcpu_init(qemu_plugin_id_t id, unsigned int cpu)
{
    if (cpu >= MAX_VCPUS) {
        return;
    }
    g_autoptr(GArray) regs = qemu_plugin_get_registers();
    VcpuState *s = &vcpus[cpu];
    for (guint i = 0; i < regs->len; i++) {
        qemu_plugin_reg_descriptor *d = &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        if (d->name[0] == 'x' && d->name[1] >= '0' && d->name[1] <= '7' && d->name[2] == '\0') {
            s->x[d->name[1] - '0'] = d->handle;
        } else if (!strcmp(d->name, "cpsr")) {
            s->cpsr = d->handle;
        } else if (!strcmp(d->name, "CONTEXTIDR_EL1")) {
            s->contextidr = d->handle;
        } else if (!strcmp(d->name, "TPIDRRO_EL0")) {
            s->tpidrro = d->handle;
        }
    }
    if (s->x[0] && (!s->contextidr || !s->tpidrro)) {
        fprintf(stderr, "hvmtrace: cpu %u lacks CONTEXTIDR_EL1/TPIDRRO_EL0, svc thread keys degraded\n", cpu);
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
        } else if (!strcmp(kv[0], "svc")) {
            log_svc = strcmp(kv[1], "off") != 0;
        }
    }
    if (!path || !(out = fopen(path, "w"))) {
        fprintf(stderr, "hvmtrace: need a writable out=<file>\n");
        return -1;
    }
    setvbuf(out, NULL, _IOFBF, 1 << 20);
    smc_returns = g_hash_table_new(g_direct_hash, g_direct_equal);
    svc_returns = g_hash_table_new(g_direct_hash, g_direct_equal);
    svc_pending = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    sm_sessions = g_hash_table_new(g_direct_hash, g_direct_equal);
    qemu_plugin_register_vcpu_init_cb(id, on_vcpu_init);
    qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_trans);
    qemu_plugin_register_atexit_cb(id, on_plugin_exit, NULL);
    return 0;
}
