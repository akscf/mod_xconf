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

#define AUDIO_BUFFER_SIZE                       2048
#define XCONF_VERSION                           "1.7"
#define XCONF_CONFIG_VERSION                    1
#define NET_ANYADDR                             "0.0.0.0"

#define DM_PAYLOAD_AUDIO                        0xAA
#define DM_PAYLOAD_COMMAND                      0xAB
#define DM_PAYLOAD_AUDIO_MAGIC                  0xFADEAFFF
#define DM_PAYLOAD_COMMAND_MAGIC                0xFADEAEEE
#define DM_MAX_NODES                            32
#define DM_NODE_LIFETIME                        60 // sec
#define DM_NODE_CHECK_INTERVAL                  (DM_NODE_LIFETIME * 2)
#define DM_SHARED_SECRET_MAX_LEN                32
#define DM_IO_BUFFER_SIZE                       4096
#define DM_MULTICAST_TTL                        1
#define DM_MODE_MILTICAST                       1
#define DM_MODE_P2P                             2
#define DM_PROTO_VERSION                        1
#define DM_SALT_SIZE                            16
#define DM_SALT_LIFE_TIME                       900 // sec

#define DMPF_ENCRYPTED                          1

#define CF_USE_TRANSCODING                      1

#define MF_SPEAKER                              1
#define MF_ADMIN                                2
#define MF_MUTED                                3
#define MF_DEAF                                 4
#define MF_KICK                                 5

typedef struct {
    switch_mutex_t          *mutex;
    switch_mutex_t          *mutex_conferences;
    switch_mutex_t          *mutex_profiles;
    switch_inthash_t        *conferences_hash;
    switch_hash_t           *conf_profiles_hash;
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
    uint8_t                 fl_ready;           //
    uint8_t                 fl_destroyed;       //
    uint8_t                 fl_au_rdy_wr;       //
    uint32_t                id;                 //
    uint32_t                flags;              //
    uint32_t                samplerate;         //
    uint32_t                channels;           //
    uint32_t                ptime;              //
    uint32_t                tx_sem;             //
    const char              *session_id;        //
    const char              *codec_name;        //
    switch_memory_pool_t    *pool;              // session pool
    switch_mutex_t          *mutex;             //
    switch_mutex_t          *mutex_audio;       //
    switch_mutex_t          *mutex_flags;       //
    switch_core_session_t   *session;           //
    switch_codec_t          *read_codec;        //
    switch_codec_t          *write_codec;       //
    //
    uint32_t                au_buffer_id;       //
    uint32_t                au_data_len;        //
    switch_byte_t           *au_buffer;         //
    //
    void                    *group;             // (member_group_t)
} member_t;

typedef struct {
    uint8_t                 fl_ready;           //
    uint8_t                 fl_destroyed;       //
    uint8_t                 fl_do_destroy;      //
    uint32_t                id;                 //
    uint32_t                capacity;           //
    uint32_t                free;               //
    uint32_t                tx_sem;             //
    switch_memory_pool_t    *pool;              // group own pool
    switch_mutex_t          *mutex;             //
    switch_mutex_t          *mutex_members;     //
    switch_inthash_t        *members;           // (member_t)
    switch_queue_t          *audio_q;           // (audio_tranfser_buffer_t)
    void                    *conference;        // (conference_t)
} member_group_t;

typedef struct {
    uint8_t                 fl_ready;           //
    uint8_t                 fl_destroyed;       //
    uint8_t                 fl_do_destroy;      //
    uint32_t                flags;              //
    uint32_t                members_count;      //
    uint32_t                speakers_count;     //
    uint32_t                tx_sem;             //
    uint32_t                groups_seq;         //
    uint32_t                members_seq;        //
    uint32_t                conf_idle_max;      //
    uint32_t                group_idle_max;     //
    uint32_t                samplerate;         //
    uint32_t                ptime;              //
    uint32_t                id;                 //
    char                    *name;              //
    switch_memory_pool_t    *pool;              // conf own pool
    switch_mutex_t          *mutex;             //
    switch_mutex_t          *mutex_flags;       //
    switch_mutex_t          *mutex_sequence;    //
    switch_mutex_t          *mutex_listeners;   //
    switch_mutex_t          *mutex_speakers;    //
    switch_inthash_t        *listeners;         // (member_group_t)
    switch_inthash_t        *speakers;          // (member_t)
    switch_hash_t           *members_idx_hash;  //
    switch_queue_t          *commands_q_in;     // (audio_tranfser_buffer_t)
    switch_queue_t          *audio_q_in;        // (audio_tranfser_buffer_t)
    switch_queue_t          *audio_q_out;       // (audio_tranfser_buffer_t)
} conference_t;

typedef struct {
    char                    *name;
    uint32_t                samplerate;
    uint32_t                ptime;
    uint32_t                conf_idle_max;      // seconds
    uint32_t                group_idle_max;     // seconds
    uint8_t                 disable_transcoding;
} conference_profile_t;

typedef struct {
    uint32_t                id;
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
