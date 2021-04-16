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
    int ival = 0;

    if(zstr(action->args)) {
       return SWITCH_STATUS_FALSE;
    }

    ival = atoi(action->args);
    if(ival == 0) {
        member->energy_level = conference->energy_level;
    } else {
        member->energy_level += ival;
    }

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t member_cmd_vol_talk_adj(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;
    int ival = 0;

    if(zstr(action->args)) {
       return SWITCH_STATUS_FALSE;
    }

    ival = atoi(action->args);
    if(ival == 0) {
        member->volume_out_lvl = 0;
    } else {
        member->volume_out_lvl += ival;
    }

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t member_cmd_vol_listen_adj(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;
    int ival = 0;

    if(zstr(action->args)) {
       return SWITCH_STATUS_FALSE;
    }

    ival = atoi(action->args);
    if(ival == 0) {
        member->volume_in_lvl = 0;
    } else {
        member->volume_in_lvl += ival;
    }

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t member_cmd_play(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    if(zstr(action->args)) {
       return SWITCH_STATUS_FALSE;
    }
    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "PLAY: conference=%s, members=%s, args=%s\n", conference->name, member->session_id, action->args);

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t member_cmd_play_stop(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "PLAY_STOP: conference=%s, members=%s, args=%s\n", conference->name, member->session_id, action->args);

    return SWITCH_STATUS_SUCCESS;
}

switch_status_t member_cmd_call_api(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;
    switch_stream_handle_t stream = { 0 };
    switch_status_t status;
    char *ptr = NULL, *cmd = NULL, *args = NULL;

    if(zstr(action->args)) {
        return SWITCH_STATUS_FALSE;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "API: conference=%s, members=%s, args=%s\n", conference->name, member->session_id, action->args);

    cmd = action->args;
    ptr = action->args;
    while (*ptr++) {
        if(*ptr == ' ') { *ptr = '\0'; args = ++ptr; break; }
    }

    SWITCH_STANDARD_STREAM(stream);

    status = switch_api_execute(cmd, args, member->session, &stream);
    if (status == SWITCH_STATUS_SUCCESS) {
        stream.write_function(&stream, "+OK\n");
    } else {
        stream.write_function(&stream, "-ERR %s\n", (stream.data ? (char *)stream.data : "unknown"));
    }

    switch_safe_free(stream.data);

    return status;
}

switch_status_t member_cmd_exec_app(void *conference_ref, void *member_ref, void *action_ref) {
    controls_profile_action_t *action = (controls_profile_action_t *) action_ref;
    conference_t *conference = (conference_t *) conference_ref;
    member_t *member = (member_t *) member_ref;
    char *ptr = NULL, *cmd = NULL, *args = NULL;

    if(zstr(action->args)) {
        return SWITCH_STATUS_FALSE;
    }

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "EXEC: conference=%s, members=%s, args=%s\n", conference->name, member->session_id, action->args);

    cmd = action->args;
    ptr = action->args;
    while (*ptr++) {
        if(*ptr == ' ') { *ptr = '\0'; args = ++ptr; break; }
    }

    return switch_core_session_execute_application(member->session, cmd, args);
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
    } else if(strncasecmp(action_str, "playback:", 9) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 9);
        action->fnc = member_cmd_play;
    } else if(strcasecmp(action_str, "stop") == 0) {
        action->args = NULL;
        action->fnc = member_cmd_play_stop;
    } else if(strncasecmp(action_str, "api:", 4) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 4);
        action->fnc = member_cmd_call_api;
    } else if(strncasecmp(action_str, "exec:", 5) == 0) {
        action->args = switch_core_strdup(profile->pool, action_str + 5);
        action->fnc = member_cmd_exec_app;
    } else {
        status = SWITCH_STATUS_FALSE;
    }

    return status;
}
