/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include "mod_xconf.h"

extern globals_t globals;
extern void launch_thread(switch_memory_pool_t *pool, switch_thread_start_t fun, void *data);

typedef struct {
    member_t    *member;
    char        *path;
    void        *dtmf_buf;
    uint32_t    dtmf_buf_len;
} member_play_thread_params_t;

switch_status_t member_payback(member_t *member, char *path, uint8_t async, void *dtmf_buf, uint32_t dtmf_buf_len);

static void *SWITCH_THREAD_FUNC member_playback_async_thread(switch_thread_t *thread, void *obj) {
    volatile member_play_thread_params_t *_ref = (member_play_thread_params_t *) obj;
    member_play_thread_params_t *params = (member_play_thread_params_t *) _ref;

    member_payback(params->member, params->path, false, params->dtmf_buf, params->dtmf_buf_len);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    switch_safe_free(params);
    return NULL;
}

switch_status_t member_payback_stop(member_t *member) {
    switch_status_t  status = SWITCH_STATUS_SUCCESS;
    int x = 0;
    switch_assert(member);

    if(member_sem_take(member)) {
        if(member_flag_test(member, MF_PLAYBACK)) {
            if(member->playpack_handle) {
                switch_mutex_lock(member->mutex_playback);
                switch_set_flag(member->playpack_handle, SWITCH_FILE_DONE);
                switch_mutex_unlock(member->mutex_playback);

                while(member_flag_test(member, MF_PLAYBACK)) {
                    if(x > 1000) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Couldn't stop playback (member: %s)\n", member->session_id);
                        status = SWITCH_STATUS_FALSE; break;
                    }
                    x++;
                    switch_yield(10000);
                }
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "member->playpack_handle == NULL (member: %s)\n", member->session_id);
                status = SWITCH_STATUS_FALSE;
                // switch_ivr_kill_uuid(member->session_id, SWITCH_CAUSE_NORMAL_TEMPORARY_FAILURE);
            }
        }
        member_sem_release(member);
    }
    return status;
}

switch_status_t member_payback(member_t *member, char *path, uint8_t async, void *dtmf_buf, uint32_t dtmf_buf_len) {
    switch_status_t  status = SWITCH_STATUS_FALSE;
    switch_channel_t *channel = NULL;
    switch_input_args_t *ap = NULL;
    switch_input_args_t args = { 0 };
    conference_t *conference = NULL;
    char *expanded = NULL, *dpath = NULL;

    switch_assert(member);

    if(zstr(path)) {
        return SWITCH_STATUS_FALSE;
    }

    if(async) {
        member_play_thread_params_t *params = NULL;

        switch_zmalloc(params, sizeof(member_play_thread_params_t));
        params->member = member;
        params->path = path;
        params->dtmf_buf = dtmf_buf;
        params->dtmf_buf_len = dtmf_buf_len;

        launch_thread(member->pool, member_playback_async_thread, params);
        return SWITCH_STATUS_SUCCESS;
    }

    if(dtmf_buf) {
        args.buf = dtmf_buf;
        args.buflen = dtmf_buf_len;
        ap = &args;
    }

    if(member_sem_take(member)) {
        channel = switch_core_session_get_channel(member->session);
        conference = ((member_group_t *) member->group)->conference;

        /* stop previous sound */
        if(member_flag_test(member, MF_PLAYBACK)) {
            if((status = member_payback_stop(member)) != SWITCH_STATUS_SUCCESS) {
                member_sem_release(member);
                goto done;
            }
        }

        /* set flags */
        switch_mutex_lock(member->mutex_playback);
        member_flag_set(member, MF_PLAYBACK, true);
        memset(member->playpack_handle, 0, sizeof(switch_file_handle_t));
        switch_mutex_unlock(member->mutex_playback);

        /* playback */
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
            } else if(!strncasecmp(path, "local_", 6) || !strncasecmp(path, "tone_", 5)) {
                status = switch_ivr_play_file(member->session, member->playpack_handle, path, ap);
            } else {
                if(switch_file_exists(path, NULL) == SWITCH_STATUS_SUCCESS) {
                    status = switch_ivr_play_file(member->session, member->playpack_handle, path, ap);
                } else {
                    if(!switch_is_file_path(path) && conference->sound_prefix_path) {
                        if(!(dpath = switch_mprintf("%s%s%s", conference->sound_prefix_path, SWITCH_PATH_SEPARATOR, path))) {
                            status = SWITCH_STATUS_MEMERR;
                        } else {
                            status = switch_ivr_play_file(member->session, member->playpack_handle, dpath, ap);
                            switch_safe_free(dpath);
                        }
                    }
                }
            }
            conference_sem_release(conference);
        }

        /* clear flags */
        switch_mutex_lock(member->mutex_playback);
        member_flag_set(member, MF_PLAYBACK, false);
        switch_mutex_unlock(member->mutex_playback);

        member_sem_release(member);
    }
done:
    switch_safe_free(expanded);
    return status;
}


