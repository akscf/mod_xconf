/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include "mod_xconf.h"
#include "cipher.h"
#include "dsp.h"
#include "utils.h"
#include "commands.h"

globals_t globals;

SWITCH_MODULE_LOAD_FUNCTION(mod_xconf_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_xconf_shutdown);
SWITCH_MODULE_DEFINITION(mod_xconf, mod_xconf_load, mod_xconf_shutdown, NULL);

static void *SWITCH_THREAD_FUNC conference_audio_capture_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC conference_audio_produce_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC conference_group_listeners_control_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC conference_control_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC dm_client_thread(switch_thread_t *thread, void *obj);
static void *SWITCH_THREAD_FUNC dm_server_thread(switch_thread_t *thread, void *obj);

// ---------------------------------------------------------------------------------------------------------------------------------------------
static void launch_thread(switch_memory_pool_t *pool, switch_thread_start_t fun, void *data) {
    switch_threadattr_t *attr = NULL;
    switch_thread_t *thread = NULL;

    switch_threadattr_create(&attr, pool);
    switch_threadattr_detach_set(attr, 1);
    switch_threadattr_stacksize_set(attr, SWITCH_THREAD_STACKSIZE);
    switch_thread_create(&thread, attr, fun, data, pool);

    switch_mutex_lock(globals.mutex);
    globals.active_threads++;
    switch_mutex_unlock(globals.mutex);

    return;
}

static switch_status_t listener_join_to_group(member_group_t **group, conference_t *conference, member_t *member) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_hash_index_t *hidx = NULL;
    switch_memory_pool_t *pool_tmp = NULL;
    member_group_t *tmp_group = NULL;
    uint8_t fl_found = false;

    switch_assert(conference);
    switch_assert(member);

    if(!conference_sem_take(conference)) {
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }

    switch_mutex_lock(conference->mutex_listeners);
    for (hidx = switch_core_hash_first_iter(conference->listeners, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
        const void *hkey = NULL; void *hval = NULL;

        switch_core_hash_this(hidx, &hkey, NULL, &hval);
        tmp_group = (member_group_t *) hval;

        if(group_sem_take(tmp_group)) {
            if(tmp_group->fl_ready) {
                switch_mutex_lock(tmp_group->mutex);
                if(tmp_group->free > 0) {
                    tmp_group->free--;

                    switch_mutex_lock(tmp_group->mutex_members);
                    switch_core_inthash_insert(tmp_group->members, member->id, member);
                    switch_mutex_unlock(tmp_group->mutex_members);

                    member->group = tmp_group;
                    *group = tmp_group;
                    fl_found = true;
                }
                switch_mutex_unlock(tmp_group->mutex);
            }
            group_sem_release(tmp_group);
        }

        if(fl_found || globals.fl_shutdown || !conference->fl_ready) {
            break;
        }
    }
    switch_mutex_unlock(conference->mutex_listeners);

    if(globals.fl_shutdown || !conference->fl_ready) {
        goto out;
    }

    if(!fl_found) {
        if(switch_core_new_memory_pool(&pool_tmp) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        if((tmp_group = switch_core_alloc(pool_tmp, sizeof(member_group_t))) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }

        switch_mutex_init(&tmp_group->mutex, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_mutex_init(&tmp_group->mutex_members, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_queue_create(&tmp_group->audio_q, globals.local_queue_size, pool_tmp);
        switch_core_inthash_init(&tmp_group->members);

        tmp_group->id = conference_assign_group_id(conference);
        tmp_group->pool = pool_tmp;
        tmp_group->conference = conference;
        tmp_group->capacity = globals.listener_group_capacity;
        tmp_group->free = tmp_group->capacity;

        tmp_group->free--;
        switch_core_inthash_insert(tmp_group->members, member->id, member);

        member->group = tmp_group;
        *group = tmp_group;
        fl_found = true;

        launch_thread(pool_tmp, conference_group_listeners_control_thread, tmp_group);

        switch_mutex_lock(conference->mutex_listeners);
        switch_core_inthash_insert(conference->listeners, tmp_group->id, tmp_group);
        switch_mutex_unlock(conference->mutex_listeners);
    }
out:
    if(status != SWITCH_STATUS_SUCCESS) {
        if(pool_tmp) {
            switch_core_destroy_memory_pool(&pool_tmp);
        }
    }

    conference_sem_release(conference);

    return status;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
static void *SWITCH_THREAD_FUNC conference_audio_capture_thread(switch_thread_t *thread, void *obj) {
    volatile conference_t *_ref = (conference_t *) obj;
    conference_t *conference = (conference_t *) _ref;
    switch_status_t status;
    switch_byte_t *src_buffer = NULL, *mix_buffer = NULL, *net_buffer = NULL;
    switch_hash_index_t *hidx = NULL;
    switch_timer_t timer = { 0 };
    switch_frame_t *read_frame = NULL;
    void *pop = NULL;
    uint32_t mix_passes = 0, mix_buffer_len = 0, src_buffer_len = 0, net_buffer_len = 0, mix_buf_channels = 0, buf_out_seq = 0;
    uint8_t fl_has_audio_local, fl_has_audio_dm;

    if(!conference_sem_take(conference)) {
        goto out;
    }

    if(switch_core_timer_init(&timer, "soft", conference->ptime, conference->samplerate, conference->pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: timer fail\n", conference->name);
        conference->fl_do_destroy = true;
        goto out;
    }
    if((src_buffer = switch_core_alloc(conference->pool, AUDIO_BUFFER_SIZE)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
        conference->fl_do_destroy = true;
        goto out;
    }
    if((mix_buffer = switch_core_alloc(conference->pool, AUDIO_BUFFER_SIZE)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
        conference->fl_do_destroy = true;
        goto out;
    }
    if((net_buffer = switch_core_alloc(conference->pool, AUDIO_BUFFER_SIZE)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
        conference->fl_do_destroy = true;
        goto out;
    }

    while(true) {
        if(globals.fl_shutdown || conference->fl_do_destroy) {
            break;
        }
        if(!conference->fl_ready) {
            switch_yield(50000);
            continue;
        }
        mix_passes = 0;
        mix_buffer_len = 0;
        src_buffer_len = 0;
        net_buffer_len = 0;
        mix_buf_channels = 0;
        fl_has_audio_local = false;
        fl_has_audio_dm = false;

        if(globals.fl_dm_enabled) {
            if(switch_queue_trypop(conference->audio_q_in, &pop) == SWITCH_STATUS_SUCCESS) {
                audio_tranfser_buffer_t *atbuf = (audio_tranfser_buffer_t *)pop;
                if(atbuf && atbuf->data_len) {
                    memcpy(net_buffer, atbuf->data, atbuf->data_len);
                    net_buffer_len = atbuf->data_len;
                    fl_has_audio_dm = true;
                }
                audio_tranfser_buffer_free(atbuf);
            }
        }

        if(conference->speakers_count > 0) {
            switch_mutex_lock(conference->mutex_speakers);
            for(hidx = switch_core_hash_first_iter(conference->speakers, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                const void *hkey = NULL; void *hval = NULL;
                member_t *speaker = NULL;

                switch_core_hash_this(hidx, &hkey, NULL, &hval);
                speaker = (member_t *) hval;

                if(member_sem_take(speaker)) {
                    if(speaker->fl_ready && !member_flag_test(speaker, MF_MUTED)) {
                        status = switch_core_session_read_frame(speaker->session, &read_frame, SWITCH_IO_FLAG_NONE, 0);
                        if(SWITCH_READ_ACCEPTABLE(status) && read_frame->samples > 0 && !switch_test_flag(read_frame, SFF_CNG)) {
                            if(conference_flag_test(conference, CF_USE_TRANSCODING)) {
                                uint32_t flags = 0;
                                uint32_t src_smprt = speaker->samplerate;
                                src_buffer_len = AUDIO_BUFFER_SIZE;

                                if(switch_core_codec_ready(speaker->read_codec)) {
                                    if(switch_core_codec_decode(speaker->read_codec, NULL, read_frame->data, read_frame->datalen, speaker->samplerate, src_buffer, &src_buffer_len, &src_smprt, &flags) == SWITCH_STATUS_SUCCESS) {
                                        if(!mix_buf_channels) {
                                            mix_buf_channels = speaker->channels;
                                        }
                                        if(mix_buf_channels != speaker->channels) {
                                            /* todo */
                                        }
                                        fl_has_audio_local = true;
                                    }
                                }

                                /* adjust volume level */
                                if(fl_has_audio_local && speaker->volume_out_lvl) {
                                    switch_change_sln_volume((int16_t *)src_buffer, ((src_buffer_len / 2) * speaker->channels), speaker->volume_out_lvl);
                                }

                                /* vad */
                                if(!speaker->vad_fade_hits) {
                                    if(fl_has_audio_local && conference_flag_test(conference, CF_USE_VAD) && member_flag_test(speaker, MF_VAD)) {
                                        int16_t *smpbuf = (int16_t *)src_buffer;
                                        uint32_t smps = src_buffer_len / sizeof(*smpbuf);
                                        uint32_t lvl = 0;

                                        for(int i = 0; i < smps; i++) {
                                            lvl += abs(smpbuf[i]);
                                        }
                                        speaker->vad_score = lvl / smps;

                                        if(speaker->vad_score > speaker->vad_lvl) {
                                            member_flag_set(speaker, MF_SPEAKING, true);
                                            speaker->vad_fade_hits = 45;
                                        } else {
                                            if(member_flag_test(speaker, MF_SPEAKING)) {
                                                fl_has_audio_local = false;
                                                member_flag_set(speaker, MF_SPEAKING, false);
                                            }
                                        }
                                    }
                                } else {
                                    // todo: correct fade effect
                                    speaker->vad_fade_hits--;
                                }

                                /* agc */
                                if(member_flag_test(speaker, MF_AGC)) {
                                    if(speaker->agc) {
                                        switch_mutex_lock(speaker->mutex_agc);
                                        switch_agc_feed(speaker->agc, (int16_t *)src_buffer, ((src_buffer_len / 2) * speaker->channels), speaker->channels);
                                        switch_mutex_unlock(speaker->mutex_agc);
                                   }
                                }

                            } else {
                                memcpy(src_buffer, read_frame->data, read_frame->datalen);
                                src_buffer_len = read_frame->datalen;
                                mix_buf_channels = speaker->channels;
                                fl_has_audio_local = true;
                                member_flag_set(speaker, MF_SPEAKING, true);
                            }
                        }
                    }
                    member_sem_release(speaker);
                }

                if(globals.fl_shutdown || conference->fl_do_destroy || conference->fl_destroyed) {
                    break;
                }

                if(fl_has_audio_local) {
                    if(!mix_passes) {
                        mix_buffer_len = src_buffer_len;
                        memcpy(mix_buffer, src_buffer, mix_buffer_len);
                    } else {
                        mix_buffer_len = (src_buffer_len < mix_buffer_len ? src_buffer_len : mix_buffer_len);
                        mix_buf(mix_buffer, src_buffer, mix_buffer_len);
                    }
                    mix_passes++;
                }

            } /* speakers iterator */
            switch_mutex_unlock(conference->mutex_speakers);
        }

        if(globals.fl_dm_enabled) {
            if(fl_has_audio_local) {
                audio_tranfser_buffer_t *atb = NULL;
                audio_tranfser_buffer_alloc(&atb, mix_buffer, mix_buffer_len);

                atb->conference_id = conference->id;
                atb->samplerate = conference->samplerate;
                atb->channels = mix_buf_channels;
                atb->id = buf_out_seq;

                if(switch_queue_trypush(globals.dm_audio_queue_out, atb) != SWITCH_STATUS_SUCCESS) {
                    audio_tranfser_buffer_free(atb);
                }
            }
        }

        if(fl_has_audio_local || fl_has_audio_dm) {
            audio_tranfser_buffer_t *atb = NULL;

            if(fl_has_audio_dm) {
                if(!mix_passes) {
                    mix_buffer_len = net_buffer_len;
                    memcpy(mix_buffer, net_buffer, mix_buffer_len);
                } else {
                    mix_buffer_len = (net_buffer_len < mix_buffer_len ? net_buffer_len : mix_buffer_len);
                    mix_buf(mix_buffer, net_buffer, mix_buffer_len);
                }
            }

            audio_tranfser_buffer_alloc(&atb, mix_buffer, mix_buffer_len);
            atb->conference_id = conference->id;
            atb->samplerate = conference->samplerate;
            atb->channels = mix_buf_channels;
            atb->id = buf_out_seq;

            if(switch_queue_trypush(conference->audio_q_out, atb) != SWITCH_STATUS_SUCCESS) {
                audio_tranfser_buffer_free(atb);
            }

            buf_out_seq++;
        }
        switch_core_timer_next(&timer);
    }
out:
    switch_core_timer_destroy(&timer);

    conference_sem_release(conference);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    return NULL;
}

static void *SWITCH_THREAD_FUNC conference_audio_produce_thread(switch_thread_t *thread, void *obj) {
    volatile conference_t *_ref = (conference_t *) obj;
    conference_t *conference = (conference_t *) _ref;
    switch_status_t status;
    switch_timer_t timer = { 0 };
    switch_hash_index_t *hidx = NULL;
    void *pop = NULL;

    if(!conference_sem_take(conference)) {
        goto out;
    }

    while(true) {
        if(globals.fl_shutdown || conference->fl_do_destroy) {
            break;
        }

        if(!conference->fl_ready) {
            switch_yield(50000);
            continue;
        }

        /* carrying audio to groups */
        while(switch_queue_trypop(conference->audio_q_out, &pop) == SWITCH_STATUS_SUCCESS) {
            audio_tranfser_buffer_t *atbuf = (audio_tranfser_buffer_t *)pop;

            if(atbuf && atbuf->data_len) {
                if(conference->members_count > 0) {

                    switch_mutex_lock(conference->mutex_listeners);
                    for (hidx = switch_core_hash_first_iter(conference->listeners, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                        const void *hkey = NULL; void *hval = NULL;
                        member_group_t *group = NULL;

                        switch_core_hash_this(hidx, &hkey, NULL, &hval);
                        group = (member_group_t *) hval;

                        if(group_sem_take(group)) {
                            if(group->fl_ready && group->free != group->capacity) {
                                audio_tranfser_buffer_t *atb_cloned = NULL;

                                audio_tranfser_buffer_clone(&atb_cloned, atbuf);
                                if(switch_queue_trypush(group->audio_q, atb_cloned) != SWITCH_STATUS_SUCCESS) {
                                    audio_tranfser_buffer_free(atb_cloned);
                                }
                            }
                            group_sem_release(group);
                        }

                        if(globals.fl_shutdown || conference->fl_do_destroy) {
                            break;
                        }
                    }
                    switch_mutex_unlock(conference->mutex_listeners);
                }
            }
            audio_tranfser_buffer_free(atbuf);
        }
        switch_yield(10000);
    }
out:
    conference_sem_release(conference);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    return NULL;
}

static void *SWITCH_THREAD_FUNC conference_group_listeners_control_thread(switch_thread_t *thread, void *obj) {
    volatile member_group_t *_ref = (member_group_t *) obj;
    member_group_t *group = (member_group_t *) _ref;
    conference_t *conference = (conference_t *) group->conference;
    const uint32_t audio_cache_size = (globals.audio_cache_size * sizeof(audio_cache_t));
    switch_byte_t *audio_cache = NULL;
    switch_byte_t *enc_buffer = NULL;
    switch_timer_t timer = { 0 };
    switch_hash_index_t *hidx = NULL;
    uint32_t group_id = group->id;
    time_t term_time = 0;
    void *pop = NULL;

    if(!conference_sem_take(conference)) {
        goto out;
    }
    if(switch_core_timer_init(&timer, "soft", conference->ptime, conference->samplerate, group->pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: timer fail\n", conference->name);
        group->fl_do_destroy = true;
        goto out;
    }
    if((enc_buffer = switch_core_alloc(group->pool, AUDIO_BUFFER_SIZE)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
        group->fl_do_destroy = true;
        goto out;
    }
    if(audio_cache_size > 0) {
        if((audio_cache = switch_core_alloc(group->pool, audio_cache_size)) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference->name);
            group->fl_do_destroy = true;
            goto out;
        }
    }

    group->fl_ready = true;

    while(true) {
        if(globals.fl_shutdown || conference->fl_do_destroy || !conference->fl_ready) {
            break;
        }
        if(term_time > 0) {
            if(group->free != group->capacity) {
                term_time = 0;
            } else if(term_time <= switch_epoch_time_now(NULL)) {
                group->fl_do_destroy = true;
                break;
            }
        }
        if(group->free == group->capacity) {
            if(conference->group_idle_max > 0 && term_time == 0) {
                term_time = (switch_epoch_time_now(NULL) + conference->group_idle_max);
            }
        }
        if(switch_queue_trypop(group->audio_q, &pop) == SWITCH_STATUS_SUCCESS) {
            audio_tranfser_buffer_t *atbuf = (audio_tranfser_buffer_t *) pop;

            if(atbuf || atbuf->data_len) {
                if(audio_cache_size) {
                    memset(audio_cache, 0x0, audio_cache_size);
                }

                switch_mutex_lock(group->mutex_members);
                for (hidx = switch_core_hash_first_iter(group->members, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                    const void *hkey = NULL; void *hval = NULL;
                    member_t *member = NULL;

                    if(globals.fl_shutdown || conference->fl_do_destroy || !conference->fl_ready) {
                        break;
                    }

                    switch_core_hash_this(hidx, &hkey, NULL, &hval);
                    member = (member_t *) hval;

                    if(member_sem_take(member)) {
                        if(!member_flag_test(member, MF_DEAF)) {
                            if(conference_flag_test(conference, CF_USE_TRANSCODING)) {
                                uint32_t flags = 0, cache_id = 0, skip_encode = false;
                                uint32_t enc_smprt = member->samplerate;
                                uint32_t enc_buffer_len = AUDIO_BUFFER_SIZE;
                                uint32_t cur_members_count = (group->capacity - group->free);

                                /* find in cache */
                                if(audio_cache_size && cur_members_count > 1) {
                                    uint32_t cname_len = 0;
                                    char cname_buf[128];

                                    cname_len = snprintf((char *)cname_buf, sizeof(cname_buf), "%s%X%X%X%X", member->codec_name, member->samplerate, member->channels, member->volume_in_lvl, atbuf->id);
                                    cache_id = make_id((char *)cname_buf, cname_len);

                                    for(int i = 0; i < globals.audio_cache_size; i++) {
                                        audio_cache_t *cache = (audio_cache_t *)(audio_cache + (i * sizeof(audio_cache_t)));
                                        if(cache->id == cache_id && cache->data_len > 0) {
                                            cache->ucnt++;
                                            enc_buffer_len = cache->data_len;
                                            memcpy((char *)enc_buffer, (char *)cache->data, cache->data_len);
                                            skip_encode = true;
                                            break;
                                        }
                                    }
                                }
                                if(!skip_encode) {

                                    /* adjust volume level */
                                    if(member->volume_in_lvl) {
                                        switch_change_sln_volume((int16_t *)atbuf->data, ((atbuf->data_len / 2) * member->channels), member->volume_in_lvl);
                                    }

                                    /* encode buffer */
                                    if(switch_core_codec_ready(member->write_codec)) {
                                        if(switch_core_codec_encode(member->write_codec, NULL, atbuf->data, atbuf->data_len, atbuf->samplerate, enc_buffer, &enc_buffer_len, &enc_smprt, &flags) == SWITCH_STATUS_SUCCESS) {
                                            if(audio_cache_size && cur_members_count > 1) {
                                                audio_cache_t *ex_cache = NULL;
                                                uint32_t min_ucnt = 0;

                                                for(int i = 0; i < globals.audio_cache_size; i++) {
                                                    audio_cache_t *cache = (audio_cache_t *)(audio_cache + (i * sizeof(audio_cache_t)));
                                                    if(!cache->id && !cache->data_len) {
                                                        ex_cache = cache;
                                                        break;
                                                    }
                                                    if(!ex_cache || cache->ucnt < ex_cache->ucnt) {
                                                        ex_cache = cache;
                                                    }
                                                }
                                                if(ex_cache) {
                                                    ex_cache->id = cache_id;
                                                    ex_cache->ucnt = 0;
                                                    ex_cache->data_len = enc_buffer_len;
                                                    memcpy((char *)ex_cache->data, (char *)enc_buffer, enc_buffer_len);
                                                }
                                            }
                                        }
                                    }
                                }
                                if(enc_buffer_len > 0) {
                                    if(member->fl_au_rdy_wr) {
                                        memcpy(member->au_buffer, enc_buffer, enc_buffer_len);

                                        switch_mutex_lock(member->mutex_audio);
                                        member->au_data_len = enc_buffer_len;
                                        member->au_buffer_id = atbuf->id;
                                        switch_mutex_unlock(member->mutex_audio);
                                    }
                                }
                            } else { /* transcoding | as-is */
                                if(member->fl_au_rdy_wr) {
                                    memcpy(member->au_buffer, atbuf->data, atbuf->data_len);

                                    switch_mutex_lock(member->mutex_audio);
                                    member->au_data_len = atbuf->data_len;
                                    member->au_buffer_id = atbuf->id;
                                    switch_mutex_unlock(member->mutex_audio);
                                }
                            }
                        } /* test membr flags */
                        member_sem_release(member);
                    }
                } /* members iterator */
                switch_mutex_unlock(group->mutex_members);
            } /* audio buffer */
            audio_tranfser_buffer_free(atbuf);
        } /* trypop audio_q */

        switch_core_timer_next(&timer);
    }
out:
    switch_core_timer_destroy(&timer);

    group->fl_ready = false;
    group->fl_destroyed = true;

    while(group->tx_sem > 0) {
        switch_yield(50000);
    }

    switch_mutex_lock(conference->mutex_listeners);
    switch_core_inthash_delete(conference->listeners, group->id);
    switch_mutex_unlock(conference->mutex_listeners);

    flush_audio_queue(group->audio_q);
    switch_queue_term(group->audio_q);

    switch_core_inthash_destroy(&group->members);
    switch_core_destroy_memory_pool(&group->pool);

    conference_sem_release(conference);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "group '%i' destroyed\n", group_id);

    return NULL;
}

static void *SWITCH_THREAD_FUNC conference_control_thread(switch_thread_t *thread, void *obj) {
    volatile conference_t *_ref = (conference_t *) obj;
    conference_t *conference = (conference_t *) _ref;
    const uint32_t conference_id = conference->id;
    char *conference_name = switch_mprintf("%s", conference->name);
    time_t term_time = 0;

    conference->fl_do_destroy = false;
    conference->fl_ready = true;

    while(true) {
        if(globals.fl_shutdown || conference->fl_do_destroy) {
            break;
        }

        if(term_time > 0) {
            if(conference->speakers_count > 0 || conference->members_count > 0) {
                term_time = 0;
            } else if(term_time <= switch_epoch_time_now(NULL)) {
                conference->fl_do_destroy = true;
                break;
            }
        }

        if(conference->speakers_count == 0 && conference->members_count == 0) {
            if(conference->conf_idle_max > 0 && term_time == 0) {
                term_time = (switch_epoch_time_now(NULL) + conference->conf_idle_max);
            }
        }
        switch_yield(10000);
    }
out:
    conference->fl_ready = false;
    conference->fl_destroyed = true;

    while(conference->tx_sem > 0) {
        switch_yield(50000);
    }

    flush_audio_queue(conference->audio_q_in);
    flush_audio_queue(conference->audio_q_out);
    switch_queue_term(conference->audio_q_in);
    switch_queue_term(conference->audio_q_out);

    flush_commands_queue(conference->commands_q_in);
    switch_queue_term(conference->commands_q_in);

    switch_core_inthash_destroy(&conference->listeners);
    switch_core_inthash_destroy(&conference->speakers);

    switch_core_hash_destroy(&conference->members_idx_hash);

    switch_core_destroy_memory_pool(&conference->pool);

    switch_mutex_lock(globals.mutex_conferences);
    switch_core_inthash_delete(globals.conferences_hash, conference_id);
    switch_mutex_unlock(globals.mutex_conferences);

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "conference '%s' destroyed\n", conference_name);

    switch_safe_free(conference_name);
    return NULL;
}

static switch_status_t init_client_socket(switch_socket_t **socket, switch_sockaddr_t **dst_addr, switch_memory_pool_t *pool) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_sockaddr_t *loaddr = NULL, *taddr = NULL;
    switch_socket_t *soc = NULL;

    switch_assert(pool);

    if((status = switch_sockaddr_info_get(&loaddr, globals.dm_local_ip, SWITCH_UNSPEC, 0, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_sockaddr_info_get) [#1]\n");
        goto out;
    }

    if(globals.dm_mode == DM_MODE_MILTICAST) {
        if((status = switch_sockaddr_info_get(&taddr, globals.dm_multicast_group, SWITCH_UNSPEC, globals.dm_port_out, 0, pool)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_sockaddr_info_get) [#2]\n");
            goto out;
        }
        *dst_addr = taddr;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "client socket: %s:%i (mcast-group: %s)\n", globals.dm_local_ip, globals.dm_port_out, globals.dm_multicast_group);
    }
    if(globals.dm_mode == DM_MODE_P2P) {
        if((status = switch_sockaddr_info_get(&taddr, globals.dm_remote_ip, SWITCH_UNSPEC, globals.dm_port_out, 0, pool)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_sockaddr_info_get) [#2]\n");
            goto out;
        }
        *dst_addr = taddr;
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "client socket: %s:%i\n", globals.dm_remote_ip, globals.dm_port_out);
    }

    if((status = switch_socket_create(&soc, switch_sockaddr_get_family(loaddr), SOCK_DGRAM, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_socket_create)\n");
        goto out;
    }
    if((status = switch_socket_bind(soc, loaddr)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_socket_bind)\n");
        goto out;
    }

    if(globals.dm_mode == DM_MODE_MILTICAST) {
        if((status = switch_mcast_interface(soc, loaddr)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_mcast_interface)\n");
            goto out;
        }
        if((status = switch_mcast_join(soc, taddr, NULL, NULL)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_mcast_join)\n");
            goto out;
        }
        if((status = switch_mcast_hops(soc, (uint8_t) DM_MULTICAST_TTL)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (cli) (switch_mcast_hops)\n");
            goto out;
        }
    }

out:
    if(soc) {
        *socket = soc;
    }
    return status;
}

static switch_status_t init_server_socket(switch_socket_t **socket, switch_memory_pool_t *pool) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_sockaddr_t *loaddr = NULL, *mcaddr = NULL;
    switch_socket_t *soc = NULL;

    switch_assert(pool);

    if(globals.dm_mode == DM_MODE_MILTICAST) {
        if((status = switch_sockaddr_info_get(&loaddr, NET_ANYADDR, SWITCH_UNSPEC, globals.dm_port_in, 0, pool)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_sockaddr_info_get) [#1]\n");
            goto out;
        }
        if((status = switch_sockaddr_info_get(&mcaddr, globals.dm_multicast_group, SWITCH_UNSPEC, 0, 0, pool)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_sockaddr_info_get) [#2]\n");
            goto out;
        }
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "server socket: %s:%i (mcast-group: %s)\n", NET_ANYADDR, globals.dm_port_in, globals.dm_multicast_group);
    }
    if(globals.dm_mode == DM_MODE_P2P) {
        if((status = switch_sockaddr_info_get(&loaddr, globals.dm_local_ip, SWITCH_UNSPEC, globals.dm_port_in, 0, pool)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_sockaddr_info_get)\n");
            goto out;
        }
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "server socket: %s:%i\n", globals.dm_local_ip, globals.dm_port_in);
    }

    if((status = switch_socket_create(&soc, switch_sockaddr_get_family(loaddr), SOCK_DGRAM, 0, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_socket_create)\n");
        goto out;
    }
    if((status = switch_socket_opt_set(soc, SWITCH_SO_REUSEADDR, true)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (opt: SWITCH_SO_REUSEADDR)\n");
        goto out;
    }
    if((status = switch_socket_bind(soc, loaddr)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_socket_bind)\n");
        goto out;
    }

    if(globals.dm_mode == DM_MODE_MILTICAST) {
        if((status = switch_mcast_join(soc, mcaddr, NULL, NULL)) != SWITCH_STATUS_SUCCESS) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (srv) (switch_mcast_join)\n");
            goto out;
        }
    }

out:
    if(soc) {
        *socket = soc;
    }
    return status;
}

static void *SWITCH_THREAD_FUNC dm_client_thread(switch_thread_t *thread, void *obj) {
    const uint32_t dm_auth_buffer_len = (strlen(globals.dm_shared_secret) + DM_SALT_SIZE);
    const uint32_t send_buffer_size = DM_IO_BUFFER_SIZE;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_memory_pool_t *pool = NULL;
    switch_socket_t *socket = NULL;
    switch_sockaddr_t *dst_addr = NULL;
    switch_byte_t *send_buffer = NULL;       /* fixed size buffer */
    switch_byte_t *dm_auth_buffer = NULL;    /* keeps salt + secret */
    switch_byte_t *paylod_data_ptr = NULL;
    cipher_ctx_t *cipher_ctx = NULL;
    dm_packet_hdr_t *phdr_ptr = NULL;
    dm_payload_audio_hdr_t *ahdr_ptr = NULL;
    uint32_t packet_seq = 0, send_len = 0;
    time_t salt_renew_time = 0;
    switch_size_t bytes = 0;
    void *pop = NULL;

    if(switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }
    if((send_buffer = switch_core_alloc(pool, send_buffer_size)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }

    if(globals.fl_dm_auth_enabled) {
        if((dm_auth_buffer = switch_core_alloc(pool, dm_auth_buffer_len)) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        switch_stun_random_string((char *)dm_auth_buffer, DM_SALT_SIZE, NULL);
        memcpy((void *)(dm_auth_buffer + DM_SALT_SIZE), globals.dm_shared_secret, strlen(globals.dm_shared_secret));
    }

    if(globals.fl_dm_encrypt_payload) {
        if((cipher_ctx = switch_core_alloc(pool, sizeof(cipher_ctx_t))) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        cipher_init(cipher_ctx, globals.dm_shared_secret, strlen(globals.dm_shared_secret));
    }

    if((status = init_client_socket(&socket, &dst_addr, pool)) != SWITCH_STATUS_SUCCESS) {
        goto out;
    }

    while(true) {
        if(globals.fl_shutdown) {
            break;
        }

        if(globals.fl_dm_auth_enabled) {
            if(!salt_renew_time || salt_renew_time < switch_epoch_time_now(NULL)) {
                switch_stun_random_string((char *)dm_auth_buffer, DM_SALT_SIZE, NULL);
                salt_renew_time = (switch_epoch_time_now(NULL) + DM_SALT_LIFE_TIME);
            }
        }

        while(switch_queue_trypop(globals.dm_command_queue_out, &pop) == SWITCH_STATUS_SUCCESS) {
            /* todo, conference commands */
        }

        while(switch_queue_trypop(globals.dm_audio_queue_out, &pop) == SWITCH_STATUS_SUCCESS) {
            audio_tranfser_buffer_t *atbuf = (audio_tranfser_buffer_t *) pop;

            if(globals.fl_shutdown) { goto out; }

            if(atbuf || atbuf->data_len) {
                send_len = (sizeof(dm_packet_hdr_t) + sizeof(dm_payload_audio_hdr_t) + atbuf->data_len);

                if(send_len <= send_buffer_size) {
                    memset((void *)send_buffer, 0x0, send_len);

                    phdr_ptr = (void *)(send_buffer);
                    ahdr_ptr = (void *)(send_buffer + sizeof(*phdr_ptr));
                    paylod_data_ptr = (void *)(send_buffer + sizeof(*phdr_ptr) + sizeof(*ahdr_ptr));

                    /* set up packet hdr */
                    phdr_ptr->node_id = globals.dm_node_id;
                    phdr_ptr->packet_id = packet_seq;
                    phdr_ptr->packet_flags = 0x0;
                    phdr_ptr->payload_type = DM_PAYLOAD_AUDIO;
                    phdr_ptr->payload_len = (sizeof(dm_payload_audio_hdr_t) + atbuf->data_len);

                    /* sign packet */
                    if(globals.fl_dm_auth_enabled) {
                        switch_md5_string((char *)phdr_ptr->auth_hash, dm_auth_buffer, dm_auth_buffer_len);
                        memcpy(phdr_ptr->auth_salt, dm_auth_buffer, DM_SALT_SIZE);
                    }

                    /* payload */
                    ahdr_ptr->magic = DM_PAYLOAD_AUDIO_MAGIC;
                    ahdr_ptr->conference_id = atbuf->conference_id;
                    ahdr_ptr->samplerate = atbuf->samplerate;
                    ahdr_ptr->channels = atbuf->channels;
                    ahdr_ptr->data_len = atbuf->data_len;

                    memcpy(paylod_data_ptr, atbuf->data, atbuf->data_len);

                    /* encrypt payload */
                    if(globals.fl_dm_encrypt_payload) {
                        uint8_t *data_ptr = (void *)(ahdr_ptr);
                        uint32_t psz = phdr_ptr->payload_len;
                        uint32_t pad = (psz % sizeof(int));

                        if(pad) { psz += sizeof(int) - pad; }
                        if(psz > send_buffer_size) { psz = phdr_ptr->payload_len; }

                        cipher_encrypt(cipher_ctx, phdr_ptr->packet_id, data_ptr, psz);
                        dm_packet_flag_set(phdr_ptr, DMPF_ENCRYPTED, true);
                    }

                    bytes = send_len;
                    switch_socket_sendto(socket, dst_addr, 0, (void *)send_buffer, &bytes);

                    packet_seq++;
                }
            } else {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "packet is too long: %i  (max: %i)\n", send_len, send_buffer_size);
            }
            audio_tranfser_buffer_free(atbuf);
        }

        switch_yield(10000);
    }

out:
    if(status != SWITCH_STATUS_SUCCESS) {
        globals.fl_shutdown = true;
    }
    if (socket) {
        switch_socket_close(socket);
    }
    if(pool) {
        switch_core_destroy_memory_pool(&pool);
    }

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    return NULL;
}

static void *SWITCH_THREAD_FUNC dm_server_thread(switch_thread_t *thread, void *obj) {
    const uint32_t dm_auth_buffer_len = (strlen(globals.dm_shared_secret) + DM_SALT_SIZE);
    const uint32_t recv_buffer_size = DM_IO_BUFFER_SIZE;
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_memory_pool_t *pool = NULL;
    switch_pollfd_t *pollfd = NULL;
    switch_socket_t *socket = NULL;
    switch_sockaddr_t *from_addr = NULL;
    switch_byte_t *recv_buffer = NULL;     /* fixed size buffer */
    switch_byte_t *dm_auth_buffer = NULL;  /* keeps salt + secret */
    switch_byte_t *paylod_data_ptr = NULL;
    switch_inthash_t *nodes_stats_map = NULL;
    switch_hash_index_t *hidx = NULL;
    cipher_ctx_t *cipher_ctx = NULL;
    char md5_hash[SWITCH_MD5_DIGEST_STRING_SIZE] = { 0 };
    dm_packet_hdr_t *phdr_ptr = NULL;
    dm_payload_audio_hdr_t *ahdr_ptr = NULL;
    conference_t *conference = NULL;
    node_stat_t *node_stat = NULL;
    switch_size_t bytes = 0;
    time_t check_seq_timer = 0;
    uint32_t nodes_count = 0;
    const char *ip_addr_remote;
    char ipbuf[48];
    int fdr = 0;

    if(switch_core_new_memory_pool(&pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }
    if(switch_core_inthash_init(&nodes_stats_map) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }
    if((recv_buffer = switch_core_alloc(pool, recv_buffer_size)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }

    if(globals.fl_dm_auth_enabled) {
        if((dm_auth_buffer = switch_core_alloc(pool, dm_auth_buffer_len)) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        memset((void *)dm_auth_buffer, 0x0, DM_SALT_SIZE);
        memcpy((void *)(dm_auth_buffer + DM_SALT_SIZE), globals.dm_shared_secret, strlen(globals.dm_shared_secret));
    }

    if(globals.fl_dm_encrypt_payload) {
        if((cipher_ctx = switch_core_alloc(pool, sizeof(cipher_ctx_t))) == NULL) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }
        cipher_init(cipher_ctx, globals.dm_shared_secret, strlen(globals.dm_shared_secret));
    }

    if((status = init_server_socket(&socket, pool)) != SWITCH_STATUS_SUCCESS) {
        goto out;
    }
    if((status = switch_socket_create_pollset(&pollfd, socket, SWITCH_POLLIN | SWITCH_POLLERR, pool)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (switch_socket_create_pollset)\n");
        goto out;
    }
    if((status = switch_socket_opt_set(socket, SWITCH_SO_NONBLOCK, true)) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "socket fail (opt: SWITCH_SO_NONBLOCK)\n");
        goto out;
    }

    switch_sockaddr_info_get(&from_addr, NULL, SWITCH_UNSPEC, 0, 0, pool);

    while(true) {
        if(globals.fl_shutdown) {
            break;
        }

        bytes = recv_buffer_size;
        if(switch_socket_recvfrom(from_addr, socket, 0, (void *)recv_buffer, &bytes) == SWITCH_STATUS_SUCCESS && bytes > sizeof(dm_packet_hdr_t)) {
            phdr_ptr = (void *)(recv_buffer);
            ip_addr_remote = switch_get_addr(ipbuf, sizeof(ipbuf), from_addr);

            if(globals.dm_node_id == phdr_ptr->node_id) {
                goto sleep;
            }

            if(!phdr_ptr->payload_len || phdr_ptr->payload_len > recv_buffer_size) {
                goto sleep;
            }

            /* check sign */
            if(globals.fl_dm_auth_enabled) {
                memcpy(dm_auth_buffer, (char *)phdr_ptr->auth_salt, DM_SALT_SIZE);
                switch_md5_string((char *)md5_hash, dm_auth_buffer, dm_auth_buffer_len);

                if(strncmp((char *)md5_hash, (char *)phdr_ptr->auth_hash, sizeof(md5_hash)) !=0) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unauthorized packet (ip: %s)\n", ip_addr_remote);
                    goto sleep;
                }
            }

            /* drop outdated packets */
            node_stat = switch_core_inthash_find(nodes_stats_map, phdr_ptr->node_id);
            if(!node_stat) {
                if(nodes_count > DM_MAX_NODES) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Too many nodes (max: %i)\n", DM_MAX_NODES);
                    goto sleep;
                }

                switch_zmalloc(node_stat, sizeof(node_stat_t));

                node_stat->node = phdr_ptr->node_id;
                node_stat->last_id = phdr_ptr->packet_id;
                node_stat->expiry = (switch_epoch_time_now(NULL) + DM_NODE_LIFETIME);

                switch_core_inthash_insert(nodes_stats_map, node_stat->node, node_stat);
                nodes_count++;

            } else {
                if(phdr_ptr->packet_id > node_stat->last_id) {
                    node_stat->last_id = phdr_ptr->packet_id;
                    node_stat->expiry = (switch_epoch_time_now(NULL) + DM_NODE_LIFETIME);
                } else {
                    goto sleep;
                }
            }

            /* decrypt payload */
            if(dm_packet_flag_test(phdr_ptr, DMPF_ENCRYPTED)) {
                if(globals.fl_dm_encrypt_payload) {
                    uint8_t *data_ptr = (void *)(recv_buffer + sizeof(*phdr_ptr));
                    uint32_t psz = phdr_ptr->payload_len;
                    uint32_t pad = (psz % sizeof(int));

                    if(pad) { psz += sizeof(int) - pad; }
                    if(psz > recv_buffer_size) { psz = phdr_ptr->payload_len; }

                    cipher_decrypt(cipher_ctx, phdr_ptr->packet_id, data_ptr, psz);
                } else {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Encrypted packet from '%s' was ignored! (encryption disabled)\n", ip_addr_remote);
                }
            }

            /* payload */
            if(phdr_ptr->payload_type == DM_PAYLOAD_AUDIO) {
                ahdr_ptr = (void *)(recv_buffer + sizeof(*phdr_ptr));
                paylod_data_ptr = (void *)(recv_buffer + sizeof(*phdr_ptr) + sizeof(*ahdr_ptr));

                /* check the magic for exclude decryption errors */
                if(ahdr_ptr->magic == DM_PAYLOAD_AUDIO_MAGIC) {
                    if(ahdr_ptr->data_len && ahdr_ptr->data_len < AUDIO_BUFFER_SIZE) {
                        conference = conference_lookup_by_id(ahdr_ptr->conference_id);

                        if(conference_sem_take(conference)) {
                            audio_tranfser_buffer_t *atbuf = NULL;
                            audio_tranfser_buffer_alloc(&atbuf, paylod_data_ptr, ahdr_ptr->data_len);

                            atbuf->conference_id = ahdr_ptr->conference_id;
                            atbuf->samplerate = ahdr_ptr->samplerate;
                            atbuf->channels = ahdr_ptr->channels;
                            atbuf->id = phdr_ptr->packet_id;

                            if(switch_queue_trypush(conference->audio_q_in, atbuf) != SWITCH_STATUS_SUCCESS) {
                                audio_tranfser_buffer_free(atbuf);
                            }
                            conference_sem_release(conference);
                        }
                    }
                } else {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Malformed payload: invalid magic (audio)!\n");
                }
            }
        }

sleep:
        if(nodes_count && check_seq_timer < switch_epoch_time_now(NULL)) {
            const void *hvar = NULL; void *hval = NULL;
            time_t ts = switch_epoch_time_now(NULL);

            for (hidx = switch_core_hash_first_iter(nodes_stats_map, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                switch_core_hash_this(hidx, &hvar, NULL, &hval);
                node_stat = (node_stat_t *)hval;
                if(node_stat && node_stat->expiry < ts) {
                    switch_core_inthash_delete(nodes_stats_map, node_stat->node);
                    switch_safe_free(node_stat);
                }
            }

            check_seq_timer = (switch_epoch_time_now(NULL) + DM_NODE_CHECK_INTERVAL);
        }

        if(pollfd) {
            switch_poll(pollfd, 1, &fdr, 10000);
        } else {
            switch_yield(10000);
        }
    }

out:
    if(status != SWITCH_STATUS_SUCCESS) {
        globals.fl_shutdown = true;
    }

    if (socket) {
        switch_socket_close(socket);
    }

    if(nodes_stats_map) {
        const void *hvar = NULL; void *hval = NULL;
        for (hidx = switch_core_hash_first_iter(nodes_stats_map, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
            switch_core_hash_this(hidx, &hvar, NULL, &hval);
            node_stat = (node_stat_t *)hval;
            if(node_stat) {
                switch_core_inthash_delete(nodes_stats_map, node_stat->node);
                switch_safe_free(node_stat);
            }
        }
        switch_safe_free(hidx);
        switch_core_inthash_destroy(&nodes_stats_map);
    }

    if(pool) {
        switch_core_destroy_memory_pool(&pool);
    }

    switch_mutex_lock(globals.mutex);
    if(globals.active_threads) globals.active_threads--;
    switch_mutex_unlock(globals.mutex);

    return NULL;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
//
// ---------------------------------------------------------------------------------------------------------------------------------------------
static void event_handler_shutdown(switch_event_t *event) {
    if(!globals.fl_shutdown) {
        globals.fl_shutdown = 1;
    }
}

#define CMD_SYNTAX "list - show conferences\n<confname> term - terminate the conferece\n<confname> show [status|groups|members]\n<confname> flags [+-][transcoding|vad|cng]\n<confname> member <uuid> kick|flags[+-|speaker|admin|mute|deaf|vad|agc]\n"
SWITCH_STANDARD_API(xconf_cmd_function) {
   char *mycmd = NULL, *argv[10] = { 0 };
    int argc = 0;

    if (!zstr(cmd)) {
        mycmd = strdup(cmd);
        switch_assert(mycmd);
        argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
    }
    if(argc == 0) {
        goto usage;
    }
    if(globals.fl_shutdown) {
        goto out;
    }

    if(argc == 1) {
        if(strcasecmp(argv[0], "list") == 0) {
            switch_hash_index_t *hidx = NULL;
            uint32_t total = 0;

            stream->write_function(stream, "active conferences: \n");

            switch_mutex_lock(globals.mutex_conferences);
            for (hidx = switch_core_hash_first_iter(globals.conferences_hash, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                const void *hkey = NULL; void *hval = NULL;

                switch_core_hash_this(hidx, &hkey, NULL, &hval);
                conference_t *conf = (conference_t *)hval;

                if(conference_sem_take(conf)) {
                    stream->write_function(stream, "%s [0x%X / %iHz / %ims] (members: %i, speakes: %i)\n", conf->name, conf->id, conf->samplerate, conf->ptime, conf->members_count, conf->speakers_count);
                    conference_sem_release(conf);
                    total++;
                }
            }
            switch_mutex_unlock(globals.mutex_conferences);

            stream->write_function(stream, "total: %i\n", total);
            goto out;
        }
        goto usage;
    }

    /* conference commands */
    char *conf_name = (argc >= 1 ? argv[0] : NULL);
    char *conf_cmd =  (argc >= 2 ? argv[1] : NULL);
    char *what_name = (argc >= 3 ? argv[2] : NULL);

    if(!conf_name || !conf_cmd) {
        goto usage;
    }

    conference_t *conf = conference_lookup_by_name(conf_name);
    if(!conf || !conf->fl_ready) {
        stream->write_function(stream, "-ERR: conference '%s' not exists\n", conf_name);
        goto out;
    }

    if(strcasecmp(conf_cmd, "show") == 0) {
        if(!what_name) { goto usage; }

        if(strcasecmp(what_name, "status") == 0) {
            stream->write_function(stream, "confrence status (only for this node):\n");
            if(conference_sem_take(conf)) {
                stream->write_function(stream, "id.......................: 0x%X\n", conf->id);
                stream->write_function(stream, "samplerate...............: %i Hz\n", conf->samplerate);
                stream->write_function(stream, "ptime....................: %i ms\n", conf->ptime);
                stream->write_function(stream, "members..................: %i\n", conf->members_count);
                stream->write_function(stream, "speakers.................: %i\n", conf->speakers_count);
                stream->write_function(stream, "conf idle timer..........: %i sec\n", conf->conf_idle_max);
                stream->write_function(stream, "group idle timer.........: %i sec\n", conf->group_idle_max);
                stream->write_function(stream, "vad level................: %i\n", conf->vad_lvl);
                stream->write_function(stream, "cng level................: %i\n", conf->comfort_noise_lvl);
                stream->write_function(stream, "user controls............: %s\n", conf->user_controls);
                stream->write_function(stream, "admin controls...........: %s\n", conf->admin_controls);
                stream->write_function(stream, "flags....................: ---------\n");
                stream->write_function(stream, "  - transcoding..........: %s\n", conference_flag_test(conf, CF_USE_TRANSCODING) ? "on" : "off");
                stream->write_function(stream, "  - vad..................: %s\n", conference_flag_test(conf, CF_USE_VAD) ? "on" : "off");
                stream->write_function(stream, "  - cng..................: %s\n", conference_flag_test(conf, CF_USE_CNG) ? "on" : "off");
                stream->write_function(stream, "  - agc..................: %s\n", conference_flag_test(conf, CF_USE_AGC) ? "on" : "off");
                conference_sem_release(conf);
            }
            goto out;
        }

        if(strcasecmp(what_name, "groups") == 0) {
            const void *hkey = NULL; void *hval = NULL;
            switch_hash_index_t *hidx = NULL;
            member_group_t *group = NULL;
            uint32_t total = 0;

            stream->write_function(stream, "conference groups:\n");

            if(conference_sem_take(conf)) {
                switch_mutex_lock(conf->mutex_listeners);
                for (hidx = switch_core_hash_first_iter(conf->listeners, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {
                    switch_core_hash_this(hidx, &hkey, NULL, &hval);
                    group = (member_group_t *) hval;
                    if(group_sem_take(group)) {
                        stream->write_function(stream, "%03i - capacity: %i, free: %i\n", group->id, group->capacity, group->free);
                        group_sem_release(group);
                        total++;
                    }
                }
                switch_mutex_unlock(conf->mutex_listeners);
                conference_sem_release(conf);
            }

            stream->write_function(stream, "total: %i\n", total);
            goto out;
        }

        if(strcasecmp(what_name, "members") == 0) {
            const void *hkey = NULL; void *hval = NULL;
            const void *hkey2 = NULL; void *hval2 = NULL;
            switch_hash_index_t *hidx = NULL, *hidx2 = NULL;
            member_group_t *group = NULL;
            member_t *member = NULL;
            uint32_t total = 0;

            stream->write_function(stream, "conference members:\n");

            if(conference_sem_take(conf)) {
                switch_mutex_lock(conf->mutex_listeners);
                for (hidx = switch_core_hash_first_iter(conf->listeners, hidx); hidx; hidx = switch_core_hash_next(&hidx)) {

                    switch_core_hash_this(hidx, &hkey, NULL, &hval);
                    group = (member_group_t *) hval;

                    if(group_sem_take(group)) {
                        switch_mutex_lock(group->mutex_members);
                        for (hidx2 = switch_core_hash_first_iter(group->members, hidx2); hidx2; hidx2 = switch_core_hash_next(&hidx2)) {

                            switch_core_hash_this(hidx2, &hkey2, NULL, &hval2);
                            member = (member_t *) hval2;

                            if(member_sem_take(member)) {
                                stream->write_function(stream, "[%s] (group:%03i, codec: %s, samplerate: %iHz, channels: %i, ptime: %ims, vol-in: %i, vol-out: %i, vad-lvl: %i, agc-lvl: %i, flags: [ %s | %s | %s | %s | %s | %s ])\n",
                                    member->session_id, group->id, member->codec_name, member->samplerate, member->channels, member->ptime,
                                    member->volume_in_lvl, member->volume_out_lvl, member->vad_lvl, member->agc_lvl,
                                    (member_flag_test(member, MF_SPEAKER) ? "+speaker" : "-speaker"),
                                    (member_flag_test(member, MF_ADMIN) ? "+admin" : "-admin"),
                                    (member_flag_test(member, MF_MUTED) ? "+muted" : "-muted"),
                                    (member_flag_test(member, MF_DEAF) ? "+deaf" : "-deaf"),
                                    (member_flag_test(member, MF_VAD) ? "+vad" : "-vad"),
                                    (member_flag_test(member, MF_AGC) ? "+agc" : "-agc")
                                );
                                member_sem_release(member);
                                total++;
                            }
                        } /* members iterator */
                        switch_mutex_unlock(group->mutex_members);
                        group_sem_release(group);
                    }
                } /* groups iterator */
                switch_mutex_unlock(conf->mutex_listeners);
                conference_sem_release(conf);
            }

            stream->write_function(stream, "total: %i\n", total);
            goto out;
        }
        goto usage;
    }

    /* conference flags */
    if(strcasecmp(conf_cmd, "flags") == 0) {
        if(argc <= 2) {
            goto usage;
        }
        if(conference_sem_take(conf)) {
            for(int i = 2; i < argc; i++) {
                uint8_t fl_op= (argv[i][0] == '+' ? true : false);
                char *fl_name = (char *)(argv[i] + 1);

                conference_parse_flags(conf, fl_name, fl_op);
            }
            conference_sem_release(conf);
        }
        goto out;
    }

    /* member actions */
    if(strcasecmp(conf_cmd, "member") == 0) {
        member_t *member = NULL;
        char *member_id = (argc >= 3 ? argv[2] : NULL);
        char *member_cmd = (argc >= 4 ? argv[3] : NULL);
        uint8_t show_usage = false;

        if(!member_cmd || !member_id) {
            goto usage;
        }

        if(conference_sem_take(conf)) {
            switch_mutex_lock(conf->mutex);
            member = switch_core_hash_find(conf->members_idx_hash, member_id);
            switch_mutex_unlock(conf->mutex);

            if(!member) {
                stream->write_function(stream, "-ERR: member '%s' not found\n", member_id);
                goto out;
            }
            if(member_sem_take(member)) {
                if(strcasecmp(member_cmd, "kick") == 0) {
                    member_flag_set(member, MF_KICK, true);

                } else if(strcasecmp(member_cmd, "flags") == 0) {
                    for(int i = 4; i < argc; i++) {
                        uint8_t fl_op = (argv[i][0] == '+' ? true : false);
                        char *fl_name = (char *)(argv[i] + 1);

                        member_parse_flags(member, fl_name, fl_op);
                    }
                } else {
                    show_usage = true;
                }
                member_sem_release(member);
            }
            conference_sem_release(conf);
        }
        if(show_usage) {goto usage; }
        goto out;
    }

    if(strcasecmp(conf_cmd, "term") == 0) {
        if(conference_sem_take(conf)) {
            if(conf->fl_ready) {
                conf->fl_do_destroy = true;
    	    }
            conference_sem_release(conf);
        }
        stream->write_function(stream, "+OK\n");
        goto out;
    }

usage:
    stream->write_function(stream, "-USAGE:\n%s\n", CMD_SYNTAX);

out:
    switch_safe_free(mycmd);
    return SWITCH_STATUS_SUCCESS;
}

#define APP_SYNTAX "confName profileName [+-flags]"
SWITCH_STANDARD_APP(xconf_app_api) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    char *mycmd = NULL, *argv[10] = { 0 }; int argc = 0;
    const char *session_id = NULL;
    switch_memory_pool_t *pool_tmp = NULL;
    switch_memory_pool_t *seesion_pool = NULL;
    conference_t *conference = NULL;
    conference_profile_t *conf_profile  = NULL;
    member_t *member = NULL;
    member_group_t *group = NULL;
    controls_profile_t *ctl_profile = NULL;
    controls_profile_action_t *ctl_action = NULL;
    switch_codec_implementation_t read_impl = { 0 };
    switch_codec_implementation_t write_impl = { 0 };
    switch_frame_t write_frame = { 0 };
    switch_timer_t timer = { 0 };
    switch_byte_t *cn_buffer = NULL;
    char dtmf_buffer[DTMF_BUFFER_SIZE] = { 0 };
    char *conference_name = NULL, *profile_name = NULL;
    uint32_t au_buffer_id_local = 0, dtmf_buf_pos = 0;
    uint32_t member_flags_old = 0, cn_buffer_size = 0;
    uint32_t conference_id;
    time_t dtmf_timer = 0;

    if (!zstr(data)) {
        mycmd = strdup(data);
        switch_assert(mycmd);
        argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
    }
    if (argc < 2) {
        goto usage;
    }
    if(globals.fl_shutdown) {
        goto out;
    }
    conference_name = argv[0];
    profile_name = argv[1];
    conference_id = make_id((char *)conference_name, strlen(conference_name));

    /* ------------------------------------------------------------------------------------------------ */
    /* looking for a conference */
    switch_mutex_lock(globals.mutex_conferences);
    conference = switch_core_inthash_find(globals.conferences_hash, conference_id);
    if(!conference) {
        conf_profile = conference_profile_lookup(profile_name);
        if(!conf_profile) {
            switch_mutex_unlock(globals.mutex_conferences);
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unknown conference profile: '%s'\n", profile_name);
            switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Profile not found!");
            switch_goto_status(SWITCH_STATUS_SUCCESS, out);
        }

        if(switch_core_new_memory_pool(&pool_tmp) != SWITCH_STATUS_SUCCESS) {
            switch_mutex_unlock(globals.mutex_conferences);
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference_name);
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }

        if((conference = switch_core_alloc(pool_tmp, sizeof(conference_t))) == NULL) {
            switch_mutex_unlock(globals.mutex_conferences);
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference_name);
            switch_goto_status(SWITCH_STATUS_GENERR, out);
        }

        switch_mutex_init(&conference->mutex, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_mutex_init(&conference->mutex_sequence, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_mutex_init(&conference->mutex_listeners, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_mutex_init(&conference->mutex_speakers, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_mutex_init(&conference->mutex_flags, SWITCH_MUTEX_NESTED, pool_tmp);
        switch_queue_create(&conference->commands_q_in, globals.local_queue_size, pool_tmp);
        switch_queue_create(&conference->audio_q_in, globals.local_queue_size, pool_tmp);
        switch_queue_create(&conference->audio_q_out, globals.local_queue_size, pool_tmp);
        switch_core_inthash_init(&conference->speakers);
        switch_core_inthash_init(&conference->listeners);
        switch_core_hash_init(&conference->members_idx_hash);

        conference->id = conference_id;
        conference->pool = pool_tmp;
        conference->name = switch_core_strdup(pool_tmp, conference_name);
        conference->samplerate = conf_profile->samplerate;
        conference->ptime = conf_profile->ptime;
        conference->conf_idle_max = conf_profile->conf_idle_max;
        conference->group_idle_max = conf_profile->group_idle_max;
        conference->vad_lvl = conf_profile->vad_level;
        conference->comfort_noise_lvl = conf_profile->comfort_noise_level;
        conference->user_controls = controls_profile_lookup(conf_profile->user_controls);
        conference->admin_controls = controls_profile_lookup(conf_profile->admin_controls);
        conference->agc_lvl = 0; // 1000
        conference->agc_low_lvl = 0;
        conference->agc_margin = 20;
        conference->agc_change_factor = 3;
        conference->agc_period_len = ((1000 / conference->ptime) * 2);
        conference->flags = 0x0;
        conference->fl_ready = false;

        conference_flag_set(conference, CF_USE_TRANSCODING, conf_profile->transcoding_enabled);
        conference_flag_set(conference, CF_USE_VAD, conf_profile->vad_enabled);
        conference_flag_set(conference, CF_USE_CNG, conf_profile->cng_enabled);
        conference_flag_set(conference, CF_USE_AGC, conf_profile->agc_enabled);

        launch_thread(pool_tmp, conference_control_thread, conference);
        launch_thread(pool_tmp, conference_audio_capture_thread, conference);
        launch_thread(pool_tmp, conference_audio_produce_thread, conference);

        switch_core_inthash_insert(globals.conferences_hash, conference_id, conference);

        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "--> conference '%s' created\n", conference->name);
    }
    switch_mutex_unlock(globals.mutex_conferences);

    /* ------------------------------------------------------------------------------------------------ */
    /* member */
    while(!conference->fl_ready) {
        if(conference->fl_destroyed || conference->fl_do_destroy) {
            goto out;
        }
        switch_yield(10000);
    }

    seesion_pool = switch_core_session_get_pool(session);
    if((member = switch_core_alloc(seesion_pool, sizeof(member_t))) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: mem fail\n", conference_name);
        switch_goto_status(SWITCH_STATUS_GENERR, out);
    }

    member->fl_ready = false;
    member->pool = seesion_pool;
    member->session = session;
    member->id = conference_assign_member_id(conference);

    switch_core_session_get_read_impl(session, &read_impl);
    switch_core_session_get_write_impl(session, &write_impl);

    switch_mutex_init(&member->mutex, SWITCH_MUTEX_NESTED, seesion_pool);
    switch_mutex_init(&member->mutex_audio, SWITCH_MUTEX_NESTED, seesion_pool);
    switch_mutex_init(&member->mutex_flags, SWITCH_MUTEX_NESTED, seesion_pool);
    switch_mutex_init(&member->mutex_agc, SWITCH_MUTEX_NESTED, seesion_pool);

    member->codec_name = switch_channel_get_variable(channel, "read_codec");
    member->session_id = switch_core_session_get_uuid(session);
    member->ptime = (read_impl.microseconds_per_packet / 1000);
    member->samplerate = read_impl.samples_per_second;
    member->channels = read_impl.number_of_channels;
    member->read_codec = switch_core_session_get_read_codec(session);
    member->write_codec = switch_core_session_get_write_codec(session);
    member->au_buffer = switch_core_session_alloc(session, AUDIO_BUFFER_SIZE);
    member->caller_id = switch_channel_get_variable(channel, "caller_id_number");
    member->flags = 0x0;
    member->fl_au_rdy_wr = true;

    session_id = member->session_id;
    write_frame.data = switch_core_session_alloc(session, AUDIO_BUFFER_SIZE);
    member->samples_ptime = (((read_impl.samples_per_second / 1000) * member->ptime) * read_impl.number_of_channels);

    if(!member->read_codec || !member->write_codec) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s: channel has no media\n", session_id);
        switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Channel has no media!");
        goto out;
    }
    if(member->au_buffer == NULL|| write_frame.data == NULL) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s: not enough memory\n", session_id);
        switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Not enough memory!");
        goto out;
    }
    if(member->samples_ptime > AUDIO_BUFFER_SIZE) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "oops: samples_per_ptime > %i (hangup session: %s)\n", AUDIO_BUFFER_SIZE, session_id);
        switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Wrong buffer size!");
        goto out;
    }
    if(switch_core_timer_init(&timer, "soft", member->ptime, member->samplerate, seesion_pool) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "%s: timer fail\n", session_id);
        switch_channel_set_variable(channel, SWITCH_CURRENT_APPLICATION_RESPONSE_VARIABLE, "Timer fail!");
        goto out;
    }

    /* comfort noises */
    cn_buffer_size = (member->samples_ptime * 2);
    cn_buffer = switch_core_session_alloc(session, cn_buffer_size);

    /* flags */
    member_flag_set(member, MF_VAD, conference_flag_test(conference, CF_USE_VAD));
    member_flag_set(member, MF_AGC, conference_flag_test(conference, CF_USE_AGC));

    for(int i = 2; i < argc; i++) {
        uint8_t fl_op = (argv[i][0] == '+' ? true : false);
        char *fl_name = (char *)(argv[i] + 1);

        member_parse_flags(member, fl_name, fl_op);
    }

    if(listener_join_to_group(&group, conference, member) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s: couldn't find group for a new member (%s)\n", conference_name, session_id);
        goto out;
    }

    member->fl_ready = true;

    /* take semaphore */
    conference_sem_take(conference);

    /* copy conf settings */
    member->agc_lvl = conference->agc_lvl;
    member->user_controls = conference->user_controls;
    member->admin_controls = conference->admin_controls;
    member->vad_lvl = conference->vad_lvl;

    /* increase membr counter */
    switch_mutex_lock(conference->mutex);
    switch_core_hash_insert(conference->members_idx_hash, member->session_id, member);
    conference->members_count++;
    switch_mutex_unlock(conference->mutex);

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "member '%s' joined to '%s' [group: %03i]\n", member->session_id, conference->name, group->id);

    switch_channel_audio_sync(channel);
    while(true) {
        if(!switch_channel_ready(channel) || globals.fl_shutdown || !conference->fl_ready) {
            break;
        }

        /* audio */
        if(member->au_data_len && au_buffer_id_local != member->au_buffer_id) {
            switch_mutex_lock(member->mutex_audio);
            member->fl_au_rdy_wr = false;
            switch_mutex_unlock(member->mutex_audio);

            write_frame.codec = member->write_codec;
            write_frame.buflen = member->au_data_len;
            write_frame.datalen = member->samples_ptime;
            write_frame.samples = member->samples_ptime;

            memcpy(write_frame.data, member->au_buffer, member->au_data_len);
            au_buffer_id_local = member->au_buffer_id;
            member->au_data_len = 0;

            switch_core_session_write_frame(session, &write_frame, SWITCH_IO_FLAG_NONE, 0);

            switch_mutex_lock(member->mutex_audio);
            member->fl_au_rdy_wr = true;
            switch_mutex_unlock(member->mutex_audio);
        } else {
            if(conference_flag_test(conference, CF_USE_CNG)) {
                uint32_t bytes = cn_buffer_size;

                if((member_generate_silence(conference, member, cn_buffer, &bytes) == SWITCH_STATUS_SUCCESS) && bytes > 0) {
                    write_frame.codec = member->write_codec;
                    write_frame.buflen = bytes;
                    write_frame.datalen = member->samples_ptime;
                    write_frame.samples = member->samples_ptime;

                    memcpy(write_frame.data, cn_buffer, bytes);
                    switch_core_session_write_frame(session, &write_frame, SWITCH_IO_FLAG_NONE, 0);
                }
            }
        }

        /* dtmf */
        if(dtmf_timer && dtmf_timer <= switch_epoch_time_now(NULL)) {
            if(dtmf_buf_pos >= 1) {
                dtmf_buffer[dtmf_buf_pos] = '\0';
                if((ctl_action = controls_profile_get_action(ctl_profile, (char *)dtmf_buffer)) != NULL) {
                    if(ctl_action->fnc(conference, member, ctl_action) != SWITCH_STATUS_SUCCESS) {
                        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "DTMF action fail\n");
                    }
                }
            }
            ctl_profile = NULL;
            ctl_action = NULL;
            dtmf_buf_pos = dtmf_timer = 0;
        }
        if(switch_channel_has_dtmf(channel)) {
            if(!ctl_profile) {
                ctl_profile = (member_flag_test(member, MF_ADMIN) ? member->admin_controls : member->user_controls);
            }
            if(ctl_profile && !ctl_profile->fl_destroyed) {
                uint8_t clr_buf = false;
                uint32_t dtmf_len = 0;
                char *p = (char *) dtmf_buffer;

                dtmf_len = switch_channel_dequeue_dtmf_string(channel, (p + dtmf_buf_pos), (DTMF_BUFFER_SIZE - dtmf_buf_pos));
                if(dtmf_len > 0) {
                    dtmf_buf_pos += dtmf_len;

                    if(!dtmf_timer && ctl_profile->digits_len_max > 1) {
                        dtmf_timer = switch_epoch_time_now(NULL) + 1; // delay 1s
                    }
                    if(dtmf_buf_pos >= ctl_profile->digits_len_max) {
                        dtmf_buffer[dtmf_buf_pos] = '\0';
                        ctl_action = controls_profile_get_action(ctl_profile, (char *)dtmf_buffer);
                        clr_buf = (ctl_action == NULL ? true : false);
                    }
                    if(clr_buf) {
                        clr_buf = false;
                        ctl_profile = NULL;
                        ctl_action = NULL;
                        dtmf_buf_pos = dtmf_timer = 0;
                    }
                    if(ctl_action) {
                        if(ctl_action->fnc(conference, member, ctl_action) != SWITCH_STATUS_SUCCESS) {
                            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "DTMF action fail\n");
                        }
                        ctl_profile = NULL;
                        ctl_action = NULL;
                        dtmf_buf_pos = dtmf_timer = 0;
                        memset((char *)dtmf_buffer, 0, DTMF_BUFFER_SIZE);
                    }
                }
            }
        }

        /* flags */
        if(member_flags_old != member->flags) {
            if(member_flag_test(member, MF_KICK)) {
                break;
            }
            /* complex op */
            switch_mutex_lock(member->mutex_flags);
            /* speaker */
            if(member_flag_test(member, MF_SPEAKER) != BIT_CHECK(member_flags_old, MF_SPEAKER)) {
                if(member_flag_test(member, MF_SPEAKER)) {
                    switch_mutex_lock(conference->mutex_speakers);
                    switch_core_inthash_insert(conference->speakers, member->id, member);
                    switch_mutex_unlock(conference->mutex_speakers);

                    switch_mutex_lock(conference->mutex);
                    conference->speakers_count++;
                    switch_mutex_unlock(conference->mutex);

                } else {
                    switch_mutex_lock(conference->mutex_speakers);
                    switch_core_inthash_insert(conference->speakers, member->id, member);
                    switch_mutex_unlock(conference->mutex_speakers);

                    switch_mutex_lock(conference->mutex);
                    conference->speakers_count--;
                    switch_mutex_unlock(conference->mutex);
                }
            }
            /* agc */
            if(member_flag_test(member, MF_AGC) != BIT_CHECK(member_flags_old, MF_AGC)) {
                if(member_flag_test(member, MF_AGC)) {
                    switch_mutex_lock(member->mutex_agc);
                    if(!member->agc) {
                        switch_agc_create(&member->agc, member->agc_lvl, conference->agc_low_lvl, conference->agc_margin, conference->agc_change_factor, conference->agc_period_len);
                        switch_agc_set_token(member->agc, switch_channel_get_name(channel));
                    } else {
                        switch_agc_set(member->agc, member->agc_lvl, conference->agc_low_lvl, conference->agc_margin, conference->agc_change_factor, conference->agc_period_len);
                    }
                    switch_mutex_unlock(member->mutex_agc);
                }
            }
            /* update local */
            member_flags_old = member->flags;
            switch_mutex_unlock(member->mutex_flags);
        }

        switch_core_timer_next(&timer);
    }
    goto out;
usage:
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "%s\n", APP_SYNTAX);

out:
    switch_core_timer_destroy(&timer);

    if(member && member->fl_ready) {
        switch_mutex_lock(member->mutex);
        member->fl_ready = false;
        member->fl_au_rdy_wr = false;
        member->fl_destroyed = true;
        switch_mutex_unlock(member->mutex);

        while(member->tx_sem > 0) {
            switch_yield(50000);
        }

        if(member_flag_test(member, MF_SPEAKER)) {
            switch_mutex_lock(conference->mutex_speakers);
            switch_core_inthash_delete(conference->speakers, member->id);
            switch_mutex_unlock(conference->mutex_speakers);

            switch_mutex_lock(conference->mutex);
            conference->speakers_count--;
            switch_mutex_unlock(conference->mutex);
        }

        if(group) {
            switch_mutex_lock(group->mutex_members);
            switch_core_inthash_delete(group->members, member->id);
            switch_mutex_unlock(group->mutex_members);

            switch_mutex_lock(group->mutex);
            if(group->free < group->capacity) {
                group->free++;
            }
            switch_mutex_unlock(group->mutex);
        }

        if(member->agc) {
            switch_agc_destroy(&member->agc);
        }

        switch_mutex_lock(conference->mutex);
        switch_core_hash_delete(conference->members_idx_hash, member->session_id);
        conference->members_count--;
        switch_mutex_unlock(conference->mutex);

        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "member '%s' left '%s'\n", member->session_id, conference->name);

        /* release semaphore */
        conference_sem_release(conference);
    }

    if(status != SWITCH_STATUS_SUCCESS) {
        if(pool_tmp) {
            switch_core_destroy_memory_pool(&pool_tmp);
        }
    }

    switch_safe_free(mycmd);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------------------------------------------------------------
#define CONFIG_NAME "xconf.conf"
SWITCH_MODULE_LOAD_FUNCTION(mod_xconf_load) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;
    switch_xml_t cfg, xml, settings, param, dmsettings, conf_profiles_xml, conf_profile_xml, ctl_profiles_xml, ctl_profile_xml, ctl_xml;
    switch_api_interface_t *commands_interface;
    switch_application_interface_t *app_interface;

    memset(&globals, 0, sizeof (globals));

    switch_core_inthash_init(&globals.conferences_hash);
    switch_core_hash_init(&globals.conferences_profiles_hash);
    switch_core_hash_init(&globals.controls_profiles_hash);

    switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, pool);
    switch_mutex_init(&globals.mutex_conferences, SWITCH_MUTEX_NESTED, pool);
    switch_mutex_init(&globals.mutex_conf_profiles, SWITCH_MUTEX_NESTED, pool);
    switch_mutex_init(&globals.mutex_controls_profiles, SWITCH_MUTEX_NESTED, pool);

    globals.dm_node_id = rand();
    globals.fl_dm_enabled = false;
    globals.fl_dm_auth_enabled = true;
    globals.fl_dm_encrypt_payload = true;
    globals.listener_group_capacity = 250;
    globals.audio_cache_size = 5;
    globals.local_queue_size = 16;
    globals.dm_queue_size = 28;
    globals.dm_port_in = 65021;
    globals.dm_port_out = 65021;

    if((xml = switch_xml_open_cfg(CONFIG_NAME, &cfg, NULL)) == NULL) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't open: %s\n", CONFIG_NAME);
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    if((settings = switch_xml_child(cfg, "settings"))) {
        for (param = switch_xml_child(settings, "param"); param; param = param->next) {
            char *var = (char *) switch_xml_attr_soft(param, "name");
            char *val = (char *) switch_xml_attr_soft(param, "value");

            if(!strcasecmp(var, "listener-group-capacity")) {
                globals.listener_group_capacity = atoi(val);
            }
        }
    }

    if((dmsettings = switch_xml_child(cfg, "distributed-mode"))) {
        char *mode = (char *) switch_xml_attr_soft(dmsettings, "mode");
        char *enabled = (char *) switch_xml_attr_soft(dmsettings, "enabled");

        globals.fl_dm_enabled = (strcasecmp(enabled, "true") == 0 ? true : false);
        globals.dm_mode_name = switch_core_strdup(pool, mode);

        for (param = switch_xml_child(dmsettings, "param"); param; param = param->next) {
            char *var = (char *) switch_xml_attr_soft(param, "name");
            char *val = (char *) switch_xml_attr_soft(param, "value");

            if(!strcasecmp(var, "auth-packets")) {
                globals.fl_dm_auth_enabled = (strcasecmp(val, "true") == 0 ? true : false);
            } else if(!strcasecmp(var, "encrypt-payload")) {
                globals.fl_dm_encrypt_payload = (strcasecmp(val, "true") == 0 ? true : false);
            } else if(!strcasecmp(var, "shared-secret")) {
                globals.dm_shared_secret = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "local-ip")) {
                globals.dm_local_ip = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "remote-ip")) {
                globals.dm_remote_ip = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "multicast-group")) {
                globals.dm_multicast_group = switch_core_strdup(pool, val);
            } else if(!strcasecmp(var, "port-in")) {
                globals.dm_port_in = atoi(val);
            } else if(!strcasecmp(var, "port-out")) {
                globals.dm_port_out = atoi(val);
            }
        }
    }

    if((ctl_profiles_xml = switch_xml_child(cfg, "controls-profiles"))) {
        for (ctl_profile_xml = switch_xml_child(ctl_profiles_xml, "profile"); ctl_profile_xml; ctl_profile_xml = ctl_profile_xml->next) {
            switch_memory_pool_t *tmp_pool = NULL;
            controls_profile_t *ctl_profile = NULL;

            char *name = (char *) switch_xml_attr_soft(ctl_profile_xml, "name");

            if(!name) { continue; }

            if(switch_core_hash_find(globals.controls_profiles_hash, name)) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Duplicated profile name: %s\n", name);
                continue;
            }

            /* create a new pool for each profile */
            if (switch_core_new_memory_pool(&tmp_pool) != SWITCH_STATUS_SUCCESS) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }

            if((ctl_profile = switch_core_alloc(tmp_pool, sizeof(controls_profile_t))) == NULL) {
                switch_core_destroy_memory_pool(&tmp_pool);
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }

            switch_core_hash_init(&ctl_profile->actions_hash);
            switch_mutex_init(&ctl_profile->mutex, SWITCH_MUTEX_NESTED, tmp_pool);

            ctl_profile->name = switch_core_strdup(tmp_pool, name);
            ctl_profile->pool = tmp_pool;
            ctl_profile->fl_destroyed = false;
            ctl_profile->digits_len_max = 0;
            ctl_profile->digits_len_min = 1;

            for (ctl_xml = switch_xml_child(ctl_profile_xml, "control"); ctl_xml; ctl_xml = ctl_xml->next) {
                controls_profile_action_t *profile_action = NULL;
                char *digits = (char *) switch_xml_attr_soft(ctl_xml, "digits");
                char *action = (char *) switch_xml_attr_soft(ctl_xml, "action");

                if(!digits || !action) { continue; }

                if(switch_core_hash_find(ctl_profile->actions_hash, digits)) {
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Duplicated action: %s (profile: %s)\n", digits, ctl_profile->name);
                    continue;
                }

                ctl_profile->digits_len_max = MAX(ctl_profile->digits_len_max, strlen(digits));
                if(ctl_profile->digits_len_max > DTMF_CMD_LEN_MAX) {
                    switch_core_destroy_memory_pool(&tmp_pool);
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "command is to long: '%s' (max: %i)\n", digits, DTMF_CMD_LEN_MAX);
                    switch_goto_status(SWITCH_STATUS_GENERR, done);
                }

                if((profile_action = switch_core_alloc(tmp_pool, sizeof(controls_profile_action_t))) == NULL) {
                    switch_core_destroy_memory_pool(&tmp_pool);
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
                    switch_goto_status(SWITCH_STATUS_GENERR, done);
                }

                profile_action->digits = switch_core_strdup(tmp_pool, digits);

                if(conf_action_parse(action, ctl_profile, profile_action) != SWITCH_STATUS_SUCCESS) {
                    switch_core_destroy_memory_pool(&tmp_pool);
                    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Unsupported action: %s\n", action);
                    switch_goto_status(SWITCH_STATUS_GENERR, done);
                }

                /* add action into profile */
                switch_core_hash_insert(ctl_profile->actions_hash, profile_action->digits, profile_action);
            }

            /* add control profile */
            switch_core_hash_insert(globals.controls_profiles_hash, ctl_profile->name, ctl_profile);
        }
    }

    if((conf_profiles_xml = switch_xml_child(cfg, "conference-profiles"))) {
        for (conf_profile_xml = switch_xml_child(conf_profiles_xml, "profile"); conf_profile_xml; conf_profile_xml = conf_profile_xml->next) {
            conference_profile_t *conf_profile = NULL;
            char *name = (char *) switch_xml_attr_soft(conf_profile_xml, "name");

            if(!name) { continue; }

            if(switch_core_hash_find(globals.conferences_profiles_hash, name)) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Duplicated profile name: %s\n", name);
                continue;
            }

            if((conf_profile = switch_core_alloc(pool, sizeof(conference_profile_t))) == NULL) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mem fail\n");
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }

            conf_profile->name = switch_core_strdup(pool, name);
            conf_profile->transcoding_enabled = true;
            conf_profile->vad_enabled = false;
            conf_profile->cng_enabled = false;
            conf_profile->agc_enabled = false;
            conf_profile->ptime = 20;
            conf_profile->samplerate = 8000;
            conf_profile->conf_idle_max = 0;
            conf_profile->group_idle_max = 0;
            conf_profile->comfort_noise_level = 0;
            conf_profile->vad_level = 0;

            for (param = switch_xml_child(conf_profile_xml, "param"); param; param = param->next) {
                char *var = (char *) switch_xml_attr_soft(param, "name");
                char *val = (char *) switch_xml_attr_soft(param, "value");

                if(!strcasecmp(var, "transcoding-enable")) {
                    conf_profile->transcoding_enabled = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "vad-enable")) {
                    conf_profile->vad_enabled = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "agc-enable")) {
                    conf_profile->agc_enabled = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "comfort-noise-enable")) {
                    conf_profile->cng_enabled = (strcasecmp(val, "true") == 0 ? true : false);
                } else if(!strcasecmp(var, "conference-idle-time-max")) {
                    conf_profile->conf_idle_max = atoi(val);
                } else if(!strcasecmp(var, "group-idle-time-max")) {
                    conf_profile->group_idle_max = atoi(val);
                } else if(!strcasecmp(var, "samplerate")) {
                    conf_profile->samplerate = atoi(val);
                } else if(!strcasecmp(var, "ptime")) {
                    conf_profile->ptime = atoi(val);
                } else if(!strcasecmp(var, "vad-level")) {
                    conf_profile->vad_level = atoi(val);
                } else if(!strcasecmp(var, "comfort-noise-level")) {
                    conf_profile->comfort_noise_level = atoi(val);
                } else if(!strcasecmp(var, "admin-controls")) {
                    conf_profile->admin_controls = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "user-controls")) {
                    conf_profile->user_controls = switch_core_strdup(pool, val);
                } else if(!strcasecmp(var, "agc-data")) {
                    conf_profile->agc_data = switch_core_strdup(pool, val);
                }
            }

            if(conf_profile->vad_level) {
                if(conf_profile->vad_level < 0 || conf_profile->vad_level > 1800) {
                    conf_profile->vad_level = 300;
                }
            }
            if(conf_profile->comfort_noise_level) {
                if(conf_profile->comfort_noise_level < 0 || conf_profile->comfort_noise_level > 10000) {
                    conf_profile->comfort_noise_level = 1400;
                }
            }
            if(conf_profile->samplerate <= 0) {
                conf_profile->samplerate = 8000;
            }
            if(conf_profile->ptime <= 0) {
                conf_profile->ptime = 20;
            }

            switch_core_hash_insert(globals.conferences_profiles_hash, conf_profile->name, conf_profile);
        }
    }

    if(globals.fl_dm_enabled) {
        if(!strcasecmp(globals.dm_mode_name, "multicast")) {
            globals.dm_mode = DM_MODE_MILTICAST;
            globals.fl_dm_enabled = true;
        } else if(!strcasecmp(globals.dm_mode_name, "p2p")) {
            globals.dm_mode = DM_MODE_P2P;
            globals.fl_dm_enabled = true;
        }

        if(!globals.dm_local_ip) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: local-ip\n");
            switch_goto_status(SWITCH_STATUS_GENERR, done);
        }
        if(!globals.dm_shared_secret || strlen(globals.dm_shared_secret) > DM_SHARED_SECRET_MAX_LEN) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: shared-secret\n");
            switch_goto_status(SWITCH_STATUS_GENERR, done);
        }
        if(globals.dm_port_in <= 0 || globals.dm_port_in > 0xffff) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: port-in!\n");
            switch_goto_status(SWITCH_STATUS_GENERR, done);
        }
        if(globals.dm_port_out <= 0 || globals.dm_port_out > 0xffff) {
            switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Invalid parameter: port-out!\n");
            switch_goto_status(SWITCH_STATUS_GENERR, done);
        }

        if(globals.dm_mode == DM_MODE_MILTICAST) {
            if(!globals.dm_multicast_group) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Multicast mode requires parameter: multicast-group\n");
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }
        }

        if(globals.dm_mode == DM_MODE_P2P) {
            if(!globals.dm_remote_ip) {
                switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "P2P mode requires parameter: remote-ip\n");
                switch_goto_status(SWITCH_STATUS_GENERR, done);
            }
        }

        char *tmp = switch_core_get_variable("core_uuid");
        if(tmp) { globals.dm_node_id = make_id(tmp, strlen(tmp)); }

        switch_queue_create(&globals.dm_audio_queue_out, globals.dm_queue_size, pool);
        switch_queue_create(&globals.dm_command_queue_out, globals.dm_queue_size, pool);

        launch_thread(pool, dm_client_thread, NULL);
        launch_thread(pool, dm_server_thread, NULL);
    }

    *module_interface = switch_loadable_module_create_module_interface(pool, modname);
    SWITCH_ADD_API(commands_interface, "xconf", "manage conferences", xconf_cmd_function, CMD_SYNTAX);
    SWITCH_ADD_APP(app_interface, "xconf", "manage conferences", "manage conferences", xconf_app_api, APP_SYNTAX, SAF_NONE);

    if (switch_event_bind(modname, SWITCH_EVENT_SHUTDOWN, SWITCH_EVENT_SUBCLASS_ANY, event_handler_shutdown, NULL) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind event handler!\n");
        switch_goto_status(SWITCH_STATUS_GENERR, done);
    }

    globals.fl_shutdown = false;

    if(globals.fl_dm_enabled) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "xconf (%s) [distributed mode] [node-id: %X / %s / encryption: %s ]\n", XCONF_VERSION, globals.dm_node_id, globals.dm_mode_name, (globals.fl_dm_encrypt_payload ? "on" : "off"));
    } else {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "xconf (%s) [standalone mode]\n", XCONF_VERSION);
    }

done:
    if(xml) {
        switch_xml_free(xml);
    }
    return status;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_xconf_shutdown) {
    switch_hash_index_t *hidx = NULL;
    void *hval = NULL;

    switch_event_unbind_callback(event_handler_shutdown);

    globals.fl_shutdown = true;
    while (globals.active_threads > 0) {
        switch_yield(50000);
    }

    if(globals.fl_dm_enabled) {
        if(globals.dm_audio_queue_out) {
            flush_audio_queue(globals.dm_audio_queue_out);
        }
        if(globals.dm_command_queue_out) {
            flush_commands_queue(globals.dm_command_queue_out);
        }
    }

    /* conferences hash */
    switch_mutex_lock(globals.mutex_conferences);
    while ((hidx = switch_core_hash_first_iter(globals.conferences_hash, hidx))) {
        switch_core_hash_this(hidx, NULL, NULL, &hval);
        conference_t *conf = (conference_t *) hval;

        if(conference_sem_take(conf)) {
            conf->fl_do_destroy = true;
            conference_sem_release(conf);
        }
    }
    switch_safe_free(hidx);
    switch_core_inthash_destroy(&globals.conferences_hash);
    switch_mutex_unlock(globals.mutex_conferences);

    /* conferences profiles hash */
    switch_mutex_lock(globals.mutex_conf_profiles);
    switch_core_hash_destroy(&globals.conferences_profiles_hash);
    switch_mutex_unlock(globals.mutex_conf_profiles);

    /* controls hash */
    switch_mutex_lock(globals.mutex_controls_profiles);
    while ((hidx = switch_core_hash_first_iter(globals.controls_profiles_hash, hidx))) {
        switch_core_hash_this(hidx, NULL, NULL, &hval);
        controls_profile_t *profile = (controls_profile_t *) hval;

        if(!profile->fl_destroyed) {
            switch_core_hash_delete(globals.controls_profiles_hash, profile->name);
            switch_core_destroy_memory_pool(&profile->pool);
        }
    }

    switch_safe_free(hidx);
    switch_core_hash_destroy(&globals.controls_profiles_hash);
    switch_mutex_unlock(globals.mutex_controls_profiles);

    return SWITCH_STATUS_SUCCESS;
}

