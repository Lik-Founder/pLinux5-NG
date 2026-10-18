/* Read-only API comparison. No kernel writes, payload stacking, or suspend. */
#include <ps5/kernel.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/sysctl.h>

/* Layout used by ps5-payload-dev/shsrv's Prospero version query. */
struct system_version {
  uint64_t size;
  char text[0x1c];
  uint32_t version;
  uint64_t extra;
};
struct padded_version {
  struct system_version value;
  unsigned char spare[256];
};
_Static_assert(sizeof(struct system_version) == 48, "system version layout");

int sceKernelGetSystemSwVersion(void *);
int sceKernelGetProsperoSystemSwVersion(void *);

int main(void) {
  printf("FW_API_READBACK_V1: read-only; no rest mode or kernel writes\n");
  printf("libc_metadata=%#x\n", kernel_get_fw_version());

  uint32_t kernel_version = 0;
  size_t length = sizeof(kernel_version);
  errno = 0;
  int rc = sysctlbyname("kern.sdk_version", &kernel_version, &length, NULL, 0);
  printf("kern.sdk_version: rc=%d errno=%d bytes=%zu raw=%#x\n",
         rc, errno, length, kernel_version);

  struct padded_version sw = {0}, prospero = {0};
  sw.value.size = sizeof(sw.value);
  prospero.value.size = sizeof(prospero.value);
  rc = sceKernelGetSystemSwVersion(&sw.value);
  printf("sceKernelGetSystemSwVersion: rc=%d size=%llu raw=%#x text=%.28s\n",
         rc, (unsigned long long)sw.value.size, sw.value.version, sw.value.text);
  rc = sceKernelGetProsperoSystemSwVersion(&prospero.value);
  printf("sceKernelGetProsperoSystemSwVersion: rc=%d size=%llu raw=%#x text=%.28s\n",
         rc, (unsigned long long)prospero.value.size,
         prospero.value.version, prospero.value.text);
  printf("FW_API_READBACK_V1: done\n");
  fflush(stdout);
  return 0;
}
