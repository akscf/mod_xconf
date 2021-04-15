/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#include "mod_xconf.h"
/**
 ** all the commands will perform in a member thread because of doesn't use locks
 **/

switch_status_t member_cmd_hangup(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    member_flag_set(member, MF_KICK, true);

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t member_cmd_deaf(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    member_flag_set(member, MF_DEAF, !member_flag_test(member, MF_DEAF));

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t member_cmd_mute(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    member_flag_set(member, MF_MUTED, !member_flag_test(member, MF_MUTED));

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t member_cmd_deaf_mute(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    member_flag_set(member, MF_DEAF, !member_flag_test(member, MF_DEAF));
    member_flag_set(member, MF_MUTED, !member_flag_test(member, MF_MUTED));

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t member_cmd_energy_adj(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "ENERGY: conference=%s, members=%s, args=%s\n", conference->name, member->session_id, action->args);

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t member_cmd_vol_talk_adj(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "VOL-TALK: conference=%s, members=%s, args=%s\n", conference->name, member->session_id, action->args);

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t member_cmd_vol_listen_adj(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "VOL-LISTEN: conference=%s, members=%s, args=%s\n", conference->name, member->session_id, action->args);

    return SWITCH_STATUS_SUCCESS;
}

/* action parser */
switch_status_t conf_action_parse(char *action_str, controls_profile_t *profile, controls_profile_action_t *action) {
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch_assert(action_str);
    switch_assert(profile);
    switch_assert(action);

    if(strcasecmp(action_str, "hangup") == 0) {
        action->args = NULL;
        action->fnc = member_cmd_hangup;
    } else if(strcasecmp(action_str, "deaf") == 0) {
        action->args = NULL;
        action->fnc = member_cmd_deaf;
    } else if(strcasecmp(action_str, "mute") == 0) {
        action->args = NULL;
        action->fnc = member_cmd_mute;
    } else if(strcasecmp(action_str, "deaf-mute") == 0) {
        action->args = NULL;
        action->fnc = member_cmd_deaf_mute;
    } else if(strncasecmp(action_str, "energy:", 7) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 7);
        action->fnc = member_cmd_energy_adj;
    } else if(strncasecmp(action_str, "vol-talk:", 9) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 9);
        action->fnc = member_cmd_vol_talk_adj;
    } else if(strncasecmp(action_str, "vol-listen:", 11) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 11);
        action->fnc = member_cmd_vol_listen_adj;
    } else {
        status = SWITCH_STATUS_FALSE;
    }

    return status;
}
