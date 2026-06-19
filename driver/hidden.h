#ifndef _WG_HIDDEN_H
#define _WG_HIDDEN_H

#include "device.h"
#include "peer.h"

#if defined(_MSC_VER)
#    define PACKED_STRUCT __pragma(pack(push, 1))
#    define END_PACKED_STRUCT __pragma(pack(pop))
#elif defined(__GNUC__) || defined(__CLANG__)
#    define PACKED_STRUCT
#    define END_PACKED_STRUCT __attribute__((packed))
#endif

#define	ERROR_HIDDEN_LEN 0xFFFF


//size_t prepare_skb_hidden(struct sk_buff *skb, struct WG_DEVICE *wg);
//
//void skb_push_hidden_handshake_cookie(void *skb, void *buffer, struct WG_DEVICE *wg);
//
//void skb_push_hidden_handshake(void *skb, void *buffer, struct WG_PEER *peer);
//
//void skb_push_hidden_data(void *skb, void *buffer, unsigned int hlen, struct WG_PEER *peer);
//
//unsigned int hidden_data_header_len(unsigned int len);


#define QUIC_START_FIELDS UINT8 flags; UINT32_BE version;
#define QUIC_END_FIELDS UINT8 token_len; UINT16_BE data_len;

PACKED_STRUCT
struct QUIC_init
{
	QUIC_START_FIELDS
	UINT8 DCID_len;
	UINT8 DCID[8];
	UINT8 SCID_len;
	UINT8 SCID[3];
	QUIC_END_FIELDS
} END_PACKED_STRUCT;

PACKED_STRUCT
struct QUIC_resp {
	QUIC_START_FIELDS
	UINT8 DCID_len;
	UINT8 DCID[3];
	UINT8 SCID_len;
	UINT8 SCID[3];
	QUIC_END_FIELDS
} END_PACKED_STRUCT;

PACKED_STRUCT
struct QUIC_cook {
	QUIC_START_FIELDS
	UINT8 DCID_len;
	UINT8 DCID[3];
	UINT8 SCID_len;
	QUIC_END_FIELDS
} END_PACKED_STRUCT;

PACKED_STRUCT
struct QUIC_data {
	UINT8 flags;
	UINT8 DCID[3];
} END_PACKED_STRUCT;

#define HIDDEN_NOIZE 31
#define HIDDEN_HS_LEN (sizeof(struct QUIC_init) + HIDDEN_NOIZE)

#endif 