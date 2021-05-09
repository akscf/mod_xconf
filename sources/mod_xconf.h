/**
 * Copyright (C) AlexandrinKS
 * https://akscf.me/
 **/
#ifndef XCONF_H
#define XCONF_H

#include <switch.h>
#include <switch_stun.h>

#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

#define AUDIO_BUFFER_SIZE                       2048 // SWITCH_RECOMMENDED_BUFFER_SIZE
#define XCONF_VERSION                           "1.7"
#define NET_ANYADDR                             "0.0.0.0"
#define DTMF_CMD_MAX_LEN                        10
#define DTMF_CMD_BUFFER_SIZE                    DTMF_CMD_MAX_LEN + 1
#define PIN_CODE_MAX_LEN                        10
#define PIN_CODE_BUFFER_SIZE                    PIN_CODE_MAX_LEN + 1
#define MEMBER_AUTH_ATTEMPTS                    3
#define MEMBER_MOH_CHECK_INTERVAL               5   // sec
#define CONF_DEFAULT_LEADIN                     20

#define DM_PAYLOAD_AUDIO                        0xA0
#define DM_PAYLOAD_VIDEO                        0xA1
#define DM_PAYLOAD_EVENT                        0xA2
#define DM_PAYLOAD_COMMAND                      0xA3
#define DM_PAYLOAD_MAGIC                        0xFADEDAF0
#define DM_MAX_NODES                            32
#define DM_NODE_LIFETIME                        60  // sec
#define DM_NODE_CHECK_INTERVAL                  (DM_NODE_LIFETIME * 2)
#define DM_SHARED_SECRET_MAX_LEN                32
#define DM_IO_BUFFER_SIZE                       4096
#define DM_MULTICAST_TTL                        1
#define DM_MODE_MILTICAST                       1
#define DM_MODE_P2P                             2   // point-to-point
#define DM_SALT_SIZE                            16
#define DM_SALT_LIFE_TIME                       900 // sec

#define DMPF_ENCRYPTED                          0x00

#define CF_AUDIO_TRANSCODE                      0x00
#define CF_VIDEO_TRANSCODE                      0x01
#define CF_USE_VAD                              0x02
#define CF_USE_CNG                              0x03
#define CF_USE_AGC                              0x04
#define CF_USE_AUTH                             0x05
#define CF_ALLOW_VIDEO                          0x06
#define CF_ALONE_SOUND                          0x07
#define CF_PLAYBACK                             0x1F

#define MF_VAD                                  0x00
#define MF_AGC                                  0x01
#define MF_CNG                                  0x02
#define MF_SPEAKER                              0x03
#define MF_ADMIN                                0x04
#define MF_MUTED                                0x05
#define MF_DEAF                                 0x06
#define MF_KICK                                 0x07
#define MF_SPEAKING                             0X08
#define MF_AUTHORIZED                           0X09
#define MF_PLAYBACK                             0x1F

typedef struct {
    switch_mutex_t          *mutex;
    switch_mutex_t          *mutex_conferences;
    switch_mutex_t          *mutex_conf_profiles;
    switch_mutex_t          *mutex_controls_profiles;
    switch_inthash_t        *conferences_hash;
    switch_hash_t           *conferences_profiles_hash;
    switch_hash_t           *controls_profiles_hash;
    uint32_t                active_threads;
    uint32_t                audio_cache_size;
    uint32_t                listener_group_capacity;
    uint32_t                local_queue_size;
    uint8_t                 fl_shutdown;
    //
    switch_queue_t          *dm_audio_queue_out;
    switch_queue_t          *dm_command_queue_out;
    char                    *dm_mode_name;
    char                    *dm_local_ip;
    char                    *dm_remote_ip;
    char                    *dm_multicast_group;
    char                    *dm_shared_secret;
    uint32_t                dm_mode;
    uint32_t                dm_node_id;
    uint32_t                dm_port_in;
    uint32_t                dm_port_out;
    uint32_t                dm_queue_size;
    uint8_t                 fl_dm_enabled;
    uint8_t                 fl_dm_auth_enabled;
    uint8_t                 fl_dm_encrypt_payload;
} globals_t;

typedef struct {
    uint8_t                 fl_destroyed;
    uint8_t                 digits_len_min;
    uint8_t                 digits_len_max;
    char                    *name;
    switch_memory_pool_t    *pool;
    switch_mutex_t          *mutex;
    switch_hash_t           *actions_hash;          // (controls_profile_action_t)
} controls_profile_t;

typedef struct {
    char                    *digits;
    char                    *args;
    switch_status_t (*fnc)(void *conference_ref, void *member_ref, void *action_ref);
} controls_profile_action_t;

typedef struct {
    uint8_t                 fl_ready;               //
    uint8_t                 fl_destroyed;           //
    uint8_t                 fl_au_rdy_wr;           //
    uint32_t                id;                     //
    uint32_t                flags;                  //
    uint32_t                samplerate;             //
    uint32_t                channels;               //
    uint32_t                ptime;                  //
    uint32_t                samples_ptime;          //
    uint32_t                tx_sem;                 //
    int32_t                 volume_in_lvl;          //
    int32_t                 volume_out_lvl;         //
    int32_t                 vad_lvl;                //
    int32_t                 vad_score;              //
    int32_t                 vad_fade_hits;          //
    int32_t                 agc_lvl;                //
    uint32_t                agc_low_lvl;            //
    uint32_t                agc_change_factor;      //
    uint32_t                agc_period_len;         //
    uint32_t                agc_margin;             //
    switch_agc_t            *agc;                   //
    const char              *session_id;            //
    const char              *caller_id;             // member number
    const char              *codec_name;            //
    switch_memory_pool_t    *pool;                  // session pool
    switch_mutex_t          *mutex;                 //
    switch_mutex_t          *mutex_agc;             //
    switch_mutex_t          *mutex_audio;           //
    switch_mutex_t          *mutex_flags;           //
    switch_mutex_t          *mutex_playback;        //
    switch_core_session_t   *session;               //
    switch_codec_t          *read_codec;            //
    switch_codec_t          *write_codec;           //
    controls_profile_t      *admin_controls;        //
    controls_profile_t      *user_controls;         //
    switch_file_handle_t    *playback_handle;       //
    //
    uint32_t                au_buffer_id;           //
    uint32_t                au_data_len;            //
    switch_byte_t           *au_buffer;             //
    //
    void                    *group;                 // (member_group_t)
} member_t;

typedef struct {
    uint8_t                 fl_ready;               //
    uint8_t                 fl_destroyed;           //
    uint8_t                 fl_do_destroy;          //
    uint32_t                id;                     //
    uint32_t                capacity;               //
    uint32_t                free;                   //
    uint32_t                tx_sem;                 //
    switch_memory_pool_t    *pool;                  // group own pool
    switch_mutex_t          *mutex;                 //
    switch_mutex_t          *mutex_members;         //
    switch_inthash_t        *members;               // (member_t)
    switch_queue_t          *audio_q;               // (audio_tranfser_buffer_t)
    void                    *conference;            // (conference_t)
} member_group_t;

typedef struct {
    uint8_t                 fl_ready;               //
    uint8_t                 fl_destroyed;           //
    uint8_t                 fl_do_destroy;          //
    uint32_t                flags;                  //
    uint32_t                members_total;          //
    uint32_t                speakers_total;         //
    uint32_t                members_local;          // this node
    uint32_t                speakers_local;         // this node
    uint32_t                tx_sem;                 //
    uint32_t                groups_seq;             //
    uint32_t                members_seq;            //
    uint32_t                conf_idle_max;          //
    uint32_t                group_idle_max;         //
    int32_t                 cng_lvl;                // comfort_noise_lvl
    int32_t                 vad_lvl;                //
    int32_t                 agc_lvl;                //
    uint32_t                agc_low_lvl;            //
    uint32_t                agc_margin;             //
    uint32_t                agc_change_factor;      //
    uint32_t                samplerate;             //
    uint32_t                channels;               //
    uint32_t                ptime;                  //
    uint32_t                id;                     //
    char                    *name;                  //
    char                    *admin_pin_code;        //
    char                    *user_pin_code;         //
    //
    char                    *sound_prefix_path;
    char                    *sound_moh;
    char                    *sound_enter_pin_code;
    char                    *sound_bad_pin_code;
    char                    *sound_member_join;
    char                    *sound_member_leave;
    char                    *sound_member_welcome;
    char                    *sound_member_bye;
    char                    *sound_member_alone;
    char                    *sound_member_kicked;
    char                    *sound_member_muted;
    char                    *sound_member_unmuted;
    char                    *sound_member_admin;
    char                    *sound_member_unadmin;
    char                    *sound_member_speaker;
    char                    *sound_member_unspeaker;
    char                    *tts_engine;
    char                    *tts_voice;
    //
    switch_memory_pool_t    *pool;                  // conf own pool
    switch_mutex_t          *mutex;                 //
    switch_mutex_t          *mutex_flags;           //
    switch_mutex_t          *mutex_sequence;        //
    switch_mutex_t          *mutex_listeners;       //
    switch_mutex_t          *mutex_speakers;        //
    switch_mutex_t          *mutex_playback;        //
    switch_inthash_t        *listeners;             // (member_group_t)
    switch_inthash_t        *speakers;              // (member_t)
    switch_hash_t           *members_idx_hash;      //
    switch_queue_t          *commands_q_in;         // (audio_tranfser_buffer_t)
    switch_queue_t          *audio_q_in;            // (audio_tranfser_buffer_t)
    switch_queue_t          *audio_q_out;           // (audio_tranfser_buffer_t)
    controls_profile_t      *admin_controls;        //
    controls_profile_t      *user_controls;         //
    switch_file_handle_t    *playback_handle;
//    switch_mutex_t          *mutex_nodes_map;
//    switch_inthash_t        *nodes_map;
} conference_t;

typedef struct {
    char                    *name;
    char                    *admin_controls;
    char                    *user_controls;
    char                    *agc_data;
    char                    *pin_code;
    char                    *admin_pin_code;
    char                    *user_pin_code;
    //
    char                    *sound_prefix_path;
    char                    *sound_moh;
    char                    *sound_enter_pin_code;
    char                    *sound_bad_pin_code;
    char                    *sound_member_join;
    char                    *sound_member_leave;
    char                    *sound_member_welcome;
    char                    *sound_member_bye;
    char                    *sound_member_alone;
    char                    *sound_member_kicked;
    char                    *sound_member_muted;
    char                    *sound_member_unmuted;
    char                    *sound_member_admin;
    char                    *sound_member_unadmin;
    char                    *sound_member_speaker;
    char                    *sound_member_unspeaker;
    char                    *tts_engine;
    char                    *tts_voice;
    //
    uint32_t                samplerate;
    uint32_t                channels;
    uint32_t                ptime;
    uint32_t                conf_idle_max;          // seconds
    uint32_t                group_idle_max;         // seconds
    int32_t                 vad_level;
    int32_t                 cng_level;
    uint8_t                 vad_enabled;
    uint8_t                 cng_enabled;
    uint8_t                 agc_enabled;
    uint8_t                 pin_auth_enabled;
    uint8_t                 audio_transcode_enabled;
    uint8_t                 video_transcode_enabled;
    uint8_t                 allow_video;
    uint8_t                 alone_sound_enabled;
} conference_profile_t;

typedef struct {
    uint32_t                id;
    uint32_t                flags;
    uint32_t                conference_id;
    uint32_t                samplerate;
    uint32_t                channels;
    uint32_t                data_len;
    switch_byte_t           *data;
} audio_tranfser_buffer_t;

typedef struct {
    uint32_t                id;
    uint32_t                ucnt;
    uint32_t                data_len;
    uint8_t                 data[AUDIO_BUFFER_SIZE];
} audio_cache_t;

typedef struct {
    uint32_t                node;
    uint32_t                last_id;
    time_t                  expiry;
} node_stat_t;

typedef struct {
    uint32_t                node_id;
    uint32_t                packet_id;
    uint32_t                packet_flags;
    uint16_t                payload_type;
    uint16_t                payload_len;
    uint8_t                 auth_salt[DM_SALT_SIZE];
    uint8_t                 auth_hash[SWITCH_MD5_DIGEST_STRING_SIZE];
} dm_packet_hdr_t;

typedef struct {
    uint32_t                magic;
    uint32_t                conference_id;
    uint32_t                samplerate;
    uint16_t                channels;
    uint16_t                data_len;
} dm_payload_audio_hdr_t;

#endif

