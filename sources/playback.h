/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include "mod_xconf.h"

switch_status_t member_payback_file(member_t *member, char *filename, uint8_t async, void *ttt) {
    switch_status_t  status = SWITCH_STATUS_SUCCESS;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "member playback: filename=%s, async=%i\n", filename, async);

    return status;
}
