#ifndef HV_DEFEAT_1360_H
#define HV_DEFEAT_1360_H

/* Firmware 13.60, non-Pro, single-cycle escape diagnostic. This interface does
 * not launch Linux; see docs/13.60-investigation.md for the missing takeover. */
int hv_defeat_1360(void);

/* Wait for the AP's all-core completion state, restore the resume hook, report
 * the diagnostic result and return to elfldr. */
int hv_defeat_1360_post_resume(void);

#endif
