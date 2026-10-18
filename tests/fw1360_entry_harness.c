/* Native dispatch fixtures only: this does not emulate or contact a PS5. */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define main payload_main
#include "../source/main.c"
#undef main

uint32_t fw;
static uint32_t raw_fixture, selected_fixture;
static int setup_result, arm_result;
static int setup_calls, arm_calls, rest_calls, post_calls;

unsigned int kernel_get_fw_version(void) { return raw_fixture; }
int setup_env(void) {
  setup_calls++;
  fw = selected_fixture;
  return setup_result;
}
void notify(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
}
unsigned int sleep(unsigned int seconds) { (void)seconds; return 0; }
void enter_rest_mode(void) { rest_calls++; }
int hv_defeat_1360(void) { arm_calls++; return arm_result; }
int hv_defeat_1360_post_resume(void) { post_calls++; return 0; }

int main(int argc, char **argv) {
  if (argc != 5) return 2;
  raw_fixture = (uint32_t)strtoul(argv[1], NULL, 0);
  selected_fixture = (uint32_t)strtoul(argv[2], NULL, 0);
  setup_result = atoi(argv[3]);
  arm_result = atoi(argv[4]);
  int result = payload_main();
  printf("NATIVE_FIXTURE_ONLY result=%d setup=%d arm=%d rest=%d post=%d\n",
         result, setup_calls, arm_calls, rest_calls, post_calls);
  return 0;
}
