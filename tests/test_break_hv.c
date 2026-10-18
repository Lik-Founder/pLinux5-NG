/* Native unit tests: ordinary heap-backed fixtures, NOT a console emulator. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "hv/defeat/resume_status.h"

void vmcb_disable_np(uint64_t *param);

struct pcpu_fixture {
  unsigned char padding[0xA8];
  uint64_t vmcb;
};
static struct pcpu_fixture pcpu[16];
static uint64_t vmcb[16][0x100 / sizeof(uint64_t)];
static uint64_t pcpus[16], oracle[3], heap, params[6];

static void reset_fixture(void) {
  memset(pcpu, 0, sizeof(pcpu));
  memset(vmcb, 0, sizeof(vmcb));
  memset(params, 0, sizeof(params));
  heap = 0;
  oracle[0] = PL5_COOKIE_HOOK_FIRED;
  oracle[1] = 0xDEADC0DE;
  oracle[2] = 0;
  params[1] = 0; /* direct map bias; all addresses below are real host pointers */
  params[2] = (uintptr_t)oracle;
  params[4] = (uintptr_t)&heap;
  params[5] = (uintptr_t)pcpus;
  for (int i = 0; i < 16; i++) {
    pcpus[i] = (uintptr_t)&pcpu[i];
    pcpu[i].vmcb = (uintptr_t)vmcb[i];
    vmcb[i][0x90 / 8] = 0xA5; /* NP_ENABLE plus unrelated bits */
    vmcb[i][0xC0 / 8] = UINT64_MAX;
  }
}

int main(void) {
  reset_fixture();
  vmcb_disable_np(params);
  assert(oracle[0] == PL5_COOKIE_HV_COMPLETE);
  assert(oracle[2] == PL5_EXPECTED_CORE_MASK);
  assert(oracle[1] == 0xDEADC0DE); /* do not overwrite the published CR3 */
  for (int i = 0; i < 16; i++) {
    assert(vmcb[i][0x90 / 8] == 0xA4);
    assert((uint32_t)vmcb[i][0xC0 / 8] == 0);
  }
  puts("all 16 VMCBs updated; unrelated control bits and CR3 retained");

  reset_fixture();
  pcpus[3] = 0;
  vmcb_disable_np(params);
  assert(oracle[0] == PL5_COOKIE_HV_INCOMPLETE);
  assert(oracle[2] == (PL5_EXPECTED_CORE_MASK & ~(1ULL << 3)));
  assert(vmcb[3][0x90 / 8] == 0xA5);
  puts("missing pcpu is not reported as a successful escape");

  reset_fixture();
  pcpu[7].vmcb = 0;
  vmcb_disable_np(params);
  assert(oracle[0] == PL5_COOKIE_HV_INCOMPLETE);
  assert(oracle[2] == (PL5_EXPECTED_CORE_MASK & ~(1ULL << 7)));
  puts("missing VMCB is not reported as a successful escape");

  reset_fixture();
  memset(pcpus, 0, sizeof(pcpus));
  vmcb_disable_np(params);
  assert(oracle[0] == PL5_COOKIE_HV_INCOMPLETE);
  assert(oracle[2] == 0);
  puts("zero updated cores is not reported as a successful escape");

  reset_fixture();
  for (int i = 0; i < 16; i++)
    vmcb[i][0x90 / 8] = 0xA4;
  vmcb_disable_np(params);
  assert(oracle[0] == PL5_COOKIE_HV_COMPLETE);
  assert(oracle[2] == PL5_EXPECTED_CORE_MASK);
  puts("already-disabled NP_ENABLE is handled idempotently");
  return 0;
}
