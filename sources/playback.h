/**
 * based on mod_conference
 *
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include "mod_xconf.h"

switch_status_t member_payback_file(member_t *member, char *path, uint8_t async, void *dtmf_buf, uint32_t dtmf_buf_len) {
    switch_status_t  status = SWITCH_STATUS_FALSE;
    switch_channel_t *channel = NULL;
    switch_input_args_t *ap = NULL;
    switch_input_args_t args = { 0 };
    conference_t *conference = NULL;
    char *expanded = NULL, *dpath = NULL;

    switch_assert(member);

    if(dtmf_buf) {
        args.buf = dtmf_buf;
        args.buflen = dtmf_buf_len;
        ap = &args;
    }

    if(member_sem_take(member)) {
        channel = switch_core_session_get_channel(member->session);
        conference = ((member_group_t *) member->group)->conference;

        if(conference_sem_take(conference)) {
            if((expanded = switch_channel_expand_variables(channel, path)) != path) {
                path = expanded;
            } else {
                expanded = NULL;
            }
            if(!strncasecmp(path, "say:", 4)) {
                if(conference->tts_engine && conference->tts_voice) {
                    status = switch_ivr_speak_text(member->session, conference->tts_engine, conference->tts_voice, path + 4, ap);
                } else {
                    status = SWITCH_STATUS_FALSE;
                }
            } else if(!strncasecmp(path, "tone_stream:", 12)) {
                status = switch_ivr_play_file(member->session, NULL, path, ap);
            } else {

                if(!switch_is_file_path(path) && conference->sound_prefix_path) {
                    if(!(dpath = switch_mprintf("%s%s%s", conference->sound_prefix_path, SWITCH_PATH_SEPARATOR, path))) {
                        status = SWITCH_STATUS_MEMERR;
                    } else {
                        status = switch_ivr_play_file(member->session, NULL, dpath, ap);
                        switch_safe_free(dpath);
                    }
                }
            }
            conference_sem_release(conference);
        }
        member_sem_release(member);
    }
    switch_safe_free(expanded);
    return status;
}
