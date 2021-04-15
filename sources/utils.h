/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include "mod_xconf.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define BIT_SET(a,b)   ((a) |= (1UL<<(b)))
#define BIT_CLEAR(a,b) ((a) &= ~(1UL<<(b)))
#define BIT_CHECK(a,b) (!!((a) & (1UL<<(b))))

extern globals_t globals;

uint32_t make_id(char *name, uint32_t len) {
    return switch_crc32_8bytes((char *)name, len);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------
controls_profile_t *controls_profile_lookup(char *name) {
    controls_profile_t *profile = NULL;

    if(!name || globals.fl_shutdown) { return NULL; }

    switch_mutex_lock(globals.mutex_controls_profiles);
    profile = switch_core_hash_find(globals.controls_profiles_hash, name);
    switch_mutex_unlock(globals.mutex_controls_profiles);

    return profile;
}

controls_profile_action_t *controls_profile_get_action(controls_profile_t *profile, char *digits) {
    controls_profile_action_t *action = NULL;

    if(!profile || !digits || profile->fl_destroyed || globals.fl_shutdown) { return NULL; }

    switch_mutex_lock(profile->mutex);
    action = switch_core_hash_find(profile->actions_hash, digits);
    switch_mutex_unlock(profile->mutex);

    return action;
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------
conference_profile_t *conference_profile_lookup(char *name) {
    conference_profile_t *profile = NULL;

    if(!name || globals.fl_shutdown) { return NULL; }

    switch_mutex_lock(globals.mutex_conf_profiles);
    profile = switch_core_hash_find(globals.conferences_profiles_hash, name);
    switch_mutex_unlock(globals.mutex_conf_profiles);

    return profile;
}

conference_t *conference_lookup_by_name(char *name) {
    conference_t *conference = NULL;
    uint32_t id = 0;

    if(!name || globals.fl_shutdown) { return NULL; }
    id = make_id(name, strlen(name));

    switch_mutex_lock(globals.mutex_conferences);
    conference = switch_core_inthash_find(globals.conferences_hash, id);
    switch_mutex_unlock(globals.mutex_conferences);

    return conference;
}

conference_t *conference_lookup_by_id(uint32_t id) {
    conference_t *conference = NULL;

    if(globals.fl_shutdown) { return NULL; }

    switch_mutex_lock(globals.mutex_conferences);
    conference = switch_core_inthash_find(globals.conferences_hash, id);
    switch_mutex_unlock(globals.mutex_conferences);

    return conference;
}

uint32_t conference_assign_member_id(conference_t *conference) {
    uint32_t id = 0;
    switch_assert(conference);

    switch_mutex_lock(conference->mutex_sequence);
    id = conference->members_seq++;
    switch_mutex_unlock(conference->mutex_sequence);

    return id;
}

uint32_t conference_assign_group_id(conference_t *conference) {
    uint32_t id = 0;

    switch_assert(conference);

    switch_mutex_lock(conference->mutex_sequence);
    id = conference->groups_seq++;
    switch_mutex_unlock(conference->mutex_sequence);

    return id;
}

/* without lock */
inline int conference_flag_test(conference_t *confrence, int flag) {
    switch_assert(confrence);
    return BIT_CHECK(confrence->flags, flag);
}

inline void conference_flag_set(conference_t *confrence, int flag, int val) {
    switch_assert(confrence);

    switch_mutex_lock(confrence->mutex_flags);
    if(val) {
        BIT_SET(confrence->flags, flag);
    } else {
        BIT_CLEAR(confrence->flags, flag);
    }
    switch_mutex_unlock(confrence->mutex_flags);
}

uint32_t conference_sem_take(conference_t *conference) {
    uint32_t status = false;

    if(!conference || globals.fl_shutdown) { return false; }

    switch_mutex_lock(conference->mutex);
    if(conference->fl_ready) {
        status = true;
        conference->tx_sem++;
    }
    switch_mutex_unlock(conference->mutex);

    return status;
}

void conference_sem_release(conference_t *conference) {
    switch_assert(conference);

    switch_mutex_lock(conference->mutex);
    if(conference->tx_sem) {
        conference->tx_sem--;
    }
    switch_mutex_unlock(conference->mutex);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------
uint32_t group_sem_take(member_group_t *group) {
    uint32_t status = false;

    if(!group || globals.fl_shutdown) { return false; }

    switch_mutex_lock(group->mutex);
    if(group->fl_ready) {
        status = true;
        group->tx_sem++;
    }
    switch_mutex_unlock(group->mutex);

    return status;
}

void group_sem_release(member_group_t *group) {
    switch_assert(group);

    switch_mutex_lock(group->mutex);
    if(group->tx_sem) {
        group->tx_sem--;
    }
    switch_mutex_unlock(group->mutex);
}

uint32_t member_sem_take(member_t *member) {
    uint32_t status = false;

    if(!member || globals.fl_shutdown) { return false; }

    switch_mutex_lock(member->mutex);
    if(member->fl_ready) {
        status = true;
        member->tx_sem++;
    }
    switch_mutex_unlock(member->mutex);

    return status;
}

void member_sem_release(member_t *member) {
    switch_assert(member);

    switch_mutex_lock(member->mutex);
    if(member->tx_sem) {
        member->tx_sem--;
    }
    switch_mutex_unlock(member->mutex);
}

/* without lock */
inline int member_flag_test(member_t *member, int flag) {
    switch_assert(member);
    return BIT_CHECK(member->flags, flag);

}

inline void member_flag_set(member_t *member, int flag, int value) {
    switch_assert(member);

    switch_mutex_lock(member->mutex_flags);
    if(value) {
        BIT_SET(member->flags, flag);
    } else {
        BIT_CLEAR(member->flags, flag);
    }
    switch_mutex_unlock(member->mutex_flags);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------
inline int dm_packet_flag_test(dm_packet_hdr_t *packet, int flag) {
    switch_assert(packet);
    return BIT_CHECK(packet->packet_flags, flag);
}

inline void dm_packet_flag_set(dm_packet_hdr_t *packet, int flag, int val) {
    switch_assert(packet);

    if(val) {
        BIT_SET(packet->packet_flags, flag);
    } else {
        BIT_CLEAR(packet->packet_flags, flag);
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------
switch_status_t audio_tranfser_buffer_alloc(audio_tranfser_buffer_t **out, switch_byte_t *data, uint32_t data_len) {
    audio_tranfser_buffer_t *buf = NULL;

    switch_zmalloc(buf, sizeof(audio_tranfser_buffer_t));

    if(data_len) {
        switch_malloc(buf->data, data_len);
        buf->data_len = data_len;
        memcpy(buf->data, data, data_len);
    }

    *out = buf;
    return SWITCH_STATUS_SUCCESS;
}

switch_status_t audio_tranfser_buffer_clone(audio_tranfser_buffer_t **dst, audio_tranfser_buffer_t *src) {
    audio_tranfser_buffer_t *buf;

    switch_assert(src);

    switch_zmalloc(buf, sizeof(audio_tranfser_buffer_t));

    buf->id = src->id;
    buf->conference_id = src->conference_id;
    buf->samplerate = src->samplerate;
    buf->channels = src->channels;
    buf->data_len = src->data_len;

    if(src->data_len) {
        switch_malloc(buf->data, src->data_len);
        memcpy(buf->data, src->data, src->data_len);
    }

    *dst = buf;
    return SWITCH_STATUS_SUCCESS;
}

void audio_tranfser_buffer_free(audio_tranfser_buffer_t *buf) {
    if(buf) {
        switch_safe_free(buf->data);
        switch_safe_free(buf);
    }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------
void flush_audio_queue(switch_queue_t *queue) {
    void *data = NULL;

    if(!queue || !switch_queue_size(queue)) {
        return;
    }
    while(switch_queue_trypop(queue, &data) == SWITCH_STATUS_SUCCESS) {
        if(data) {
            audio_tranfser_buffer_free((audio_tranfser_buffer_t *)data);
        }
    }
}

void flush_commands_queue(switch_queue_t *queue) {
    void *data = NULL;

    if(!queue || !switch_queue_size(queue)) {
        return;
    }
    while(switch_queue_trypop(queue, &data) == SWITCH_STATUS_SUCCESS) {
        if(data) {
            //
        }
    }
}
