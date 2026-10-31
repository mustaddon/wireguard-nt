#include "hidden.h"
#include "messages.h"
#include "peerlookup.h"
#include "queueing.h"


#define XOR_HEAD(skb, mask) ((UINT8 *)(skb))[0]=(((UINT8 *)(skb))[0]&0xF0)|((((UINT8 *)(skb))[0]^((UINT8 *)(mask))[3])&0x0F)
#define MASK_HLEN(val, mask) ((val)^((UINT8 *)(mask))[7])
#define SKB_HLEN(skb, qlen, mask) ((((UINT8 *)(skb))[0]&1) == 0 ? qlen : qlen + MASK_HLEN(((UINT8 *)(skb))[qlen], mask))


static VOID xor_mac2(VOID *skb, SIZE_T len, UINT32 zero, UINT32 *mask)
{
   UINT32 UNALIGNED *ptr = (UINT32 UNALIGNED *)((UINT8 *)skb + len - 16);
   ptr[0] ^= zero^mask[4];
   ptr[1] ^= zero^mask[5];
   ptr[2] ^= zero^mask[6];
   ptr[3] ^= zero^mask[7];
}

static VOID xor_init(VOID *skb, UINT32 *mask)
{
   UINT32 UNALIGNED *ptr = (UINT32 UNALIGNED *)(skb);
   UINT32 zero = ptr[0]^mask[0];
   ptr[1] ^= zero^mask[1];
   xor_mac2(skb, sizeof(MESSAGE_HANDSHAKE_INITIATION), zero, mask);
}

static VOID xor_resp(VOID *skb, UINT32 *mask)
{
   UINT32 UNALIGNED *ptr = (UINT32 UNALIGNED *)(skb);
   UINT32 zero = ptr[0]^mask[0];
   ptr[1] ^= zero^mask[1];
   ptr[2] ^= zero^mask[2];
   xor_mac2(skb, sizeof(MESSAGE_HANDSHAKE_RESPONSE), zero, mask);
}

static VOID xor_cook(VOID *skb, UINT32 *mask)
{
   UINT32 UNALIGNED *ptr = (UINT32 UNALIGNED *)(skb);
   UINT32 zero = ptr[0]^mask[0];
   ptr[1] ^= zero^mask[1];
}

static VOID xor_data(VOID *skb, UINT32 *mask)
{
   UINT32 UNALIGNED *ptr = (UINT32 UNALIGNED *)(skb);
   UINT32 zero = ptr[0]^mask[0];
   ptr[1] ^= zero^mask[1];
   ptr[2] ^= zero^mask[2];
   ptr[3] ^= zero^mask[3];
}


_Use_decl_annotations_
BOOLEAN PrepareNetBufferListHidden(NET_BUFFER_LIST *Nbl, WG_DEVICE *wg) 
{
    WSK_BUF *buffer = &NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl)->Buffer;
    if (buffer->Length < MESSAGE_MINIMUM_LENGTH)
        return FALSE;
    
    UINT8 *data = MemGetValidatedNetBufferListData(Nbl);
    if (!NT_SUCCESS(MemCopyFromMdl(data, buffer->Mdl, buffer->Offset, MESSAGE_MINIMUM_LENGTH)))
        return FALSE;

    XOR_HEAD(data, wg->StaticIdentity.StaticPublic);

    int type;
    ULONG hlen;

#define __add_offset_and_pull_data(len) \
    buffer->Offset += hlen; \
    buffer->Length -= hlen; \
    NET_BUFFER_DATA_LENGTH(NET_BUFFER_LIST_FIRST_NB(Nbl)) -= hlen; \
    if (!NT_SUCCESS(MemCopyFromMdl(data, buffer->Mdl, buffer->Offset, len))) return FALSE;

//#define __add_offset_and_pull_data(len) \
//    NdisAdvanceNetBufferDataStart(NET_BUFFER_LIST_FIRST_NB(Nbl), hlen, FALSE, NULL); \
//    buffer->Offset += hlen; \
//    buffer->Length -= hlen; \
//    data = MemGetValidatedNetBufferListData(Nbl); \
//    if (!data || !NT_SUCCESS(MemCopyFromMdl(data, buffer->Mdl, buffer->Offset, len))) return FALSE;


    if ((data[0] & 0x80) == 0)
    {
        type = MESSAGE_TYPE_DATA;

        if ((data[0] & 1))
        {
            hlen = SKB_HLEN(data, sizeof(struct QUIC_data), wg->StaticIdentity.StaticPublic);
            if (buffer->Length < hlen + MESSAGE_MINIMUM_LENGTH)
                return FALSE;
            __add_offset_and_pull_data(sizeof(MESSAGE_DATA));
        }

        xor_data(data, (UINT32 *)wg->StaticIdentity.StaticPublic);
    }
    else
    {
        if(data[5] != 3)
        {
            type = MESSAGE_TYPE_HANDSHAKE_INITIATION;
            hlen = SKB_HLEN(data, sizeof(struct QUIC_init), wg->StaticIdentity.StaticPublic);
            if (buffer->Length < hlen + sizeof(MESSAGE_HANDSHAKE_INITIATION))
                return FALSE;
            __add_offset_and_pull_data(sizeof(MESSAGE_HANDSHAKE_INITIATION));
            xor_init(data, (UINT32 *)wg->StaticIdentity.StaticPublic);
        }
        else if(data[9] != 0)
        {
            type = MESSAGE_TYPE_HANDSHAKE_RESPONSE;
            hlen = SKB_HLEN(data, sizeof(struct QUIC_resp), wg->StaticIdentity.StaticPublic);
            if (buffer->Length < hlen + sizeof(MESSAGE_HANDSHAKE_RESPONSE))
                return FALSE;
            __add_offset_and_pull_data(sizeof(MESSAGE_HANDSHAKE_RESPONSE));
            xor_resp(data, (UINT32 *)wg->StaticIdentity.StaticPublic);
        }
        else 
        {
            type = MESSAGE_TYPE_HANDSHAKE_COOKIE;
            hlen = SKB_HLEN(data, sizeof(struct QUIC_cook), wg->StaticIdentity.StaticPublic);
            if (buffer->Length < hlen + sizeof(MESSAGE_HANDSHAKE_COOKIE))
                return FALSE;
            __add_offset_and_pull_data(sizeof(MESSAGE_HANDSHAKE_COOKIE));
            xor_cook(data, (UINT32 *)wg->StaticIdentity.StaticPublic);
        }
    }

    ((UINT32_LE UNALIGNED *)(data))[0] = CpuToLe32(type);

    return TRUE;
}

#undef __add_offset_and_pull_data

#define QUIC_START(flags) \
   quic->flags = flags; \
   quic->version = CpuToBe32(1);

#define QUIC_END(data, quic, hlen) \
   quic->token_len = 0; \
   quic->data_len = CpuToBe16(0x4000 | (sizeof(*data)+hlen));

#define QUIC_HLEN(quic, hlen, mask) \
   if (hlen > 0) { \
       if (hlen > 1) CryptoRandom((UINT8 *)quic+sizeof(*quic)+1, hlen-1); \
       ((UINT8 *)quic)[sizeof(*quic)]=(UINT8)MASK_HLEN(hlen, mask); \
    }

static VOID add_quick_init(
   MESSAGE_HANDSHAKE_INITIATION *data, 
   struct QUIC_init *quic,
   UINT8 flags,
   SIZE_T hlen,
   UINT8 *mask)
{
   QUIC_START(flags);

   quic->DCID_len = sizeof(quic->DCID);
   CryptoRandom(quic->DCID, sizeof(quic->DCID));

   quic->SCID_len = sizeof(quic->SCID);
   memcpy(quic->SCID, &data->SenderIndex, sizeof(quic->SCID));

   QUIC_END(data, quic, hlen);
   QUIC_HLEN(quic, hlen, mask);
}

static VOID add_quick_resp(
   MESSAGE_HANDSHAKE_RESPONSE *data, 
   struct QUIC_resp *quic,
   UINT8 flags,
   SIZE_T hlen,
   UINT8 *mask)
{
   QUIC_START(flags);

   quic->DCID_len = sizeof(quic->DCID);
   memcpy(quic->DCID, &data->ReceiverIndex, sizeof(quic->DCID));

   quic->SCID_len = sizeof(quic->SCID);
   memcpy(quic->SCID, &data->SenderIndex, sizeof(quic->SCID));

   QUIC_END(data, quic, hlen);
   QUIC_HLEN(quic, hlen, mask);
}

static VOID add_quick_cook(
   MESSAGE_HANDSHAKE_COOKIE *data, 
   struct QUIC_cook *quic,
   UINT8 flags,
   SIZE_T hlen,
   UINT8 *mask)
{
   QUIC_START(flags);

   quic->DCID_len = sizeof(quic->DCID);
   memcpy(quic->DCID, &data->ReceiverIndex, sizeof(quic->DCID));

   quic->SCID_len = 0;

   QUIC_END(data, quic, hlen);
   QUIC_HLEN(quic, hlen, mask);
}

VOID AddHiddenHandshake(WSK_BUF *wsk, UINT8 *buffer, WG_PEER *peer)
{
    UINT8 *quic = MmGetMdlVirtualAddress(wsk->Mdl);
    if (!quic) return;

    UINT8 type = buffer[0];
    CryptoRandom(buffer, sizeof(UINT32));
    ULONG hlen = buffer[0]&HIDDEN_NOIZE;
    UINT8 flags = (hlen>0 ? 0xC1 : 0xC0) | (buffer[1]&0x0E);
   
    switch (type) {
        case MESSAGE_TYPE_HANDSHAKE_INITIATION:
            wsk->Length += sizeof(struct QUIC_init) + hlen;
            add_quick_init(
                (MESSAGE_HANDSHAKE_INITIATION *)buffer,
                (struct QUIC_init *)quic, 
                flags, hlen, peer->Handshake.RemoteStatic);
            xor_init(buffer, (UINT32 *)peer->Handshake.RemoteStatic);
            break;

        case MESSAGE_TYPE_HANDSHAKE_RESPONSE:
            wsk->Length += sizeof(struct QUIC_resp) + hlen;
            add_quick_resp(
                (MESSAGE_HANDSHAKE_RESPONSE *)buffer,
                (struct QUIC_resp *)quic, 
                flags, hlen, peer->Handshake.RemoteStatic);
            xor_resp(buffer, (UINT32 *)peer->Handshake.RemoteStatic);
            break;

        case MESSAGE_TYPE_HANDSHAKE_COOKIE:
            wsk->Length += sizeof(struct QUIC_cook) + hlen;
            add_quick_cook(
                (MESSAGE_HANDSHAKE_COOKIE *)buffer,
                (struct QUIC_cook *)quic, 
                flags, hlen, peer->Handshake.RemoteStatic);
            xor_cook(buffer, (UINT32 *)peer->Handshake.RemoteStatic);
            break;
    }

    XOR_HEAD(quic, peer->Handshake.RemoteStatic);
}

VOID AddHiddenHandshakeCookie(WSK_BUF *wsk, UINT8 *buffer, WG_DEVICE *wg)
{
    WG_PEER *peer = NULL;

    if (!IndexHashtableLookup(
            wg->IndexHashtable, 
            INDEX_HASHTABLE_HANDSHAKE | INDEX_HASHTABLE_KEYPAIR, 
            ((MESSAGE_HANDSHAKE_COOKIE *)buffer)->ReceiverIndex, 
            &peer))
        return;
   
    AddHiddenHandshake(wsk, buffer, peer);
}

ULONG AddHiddenData(UINT8 *quic, MESSAGE_DATA *buffer, WG_PEER *peer, BOOLEAN isKeepalive)
{
    ULONG hlen = 0;

    if (!isKeepalive) 
    {
        quic = (UINT8 *)buffer;
        quic[0] = (((UINT8)KeQueryInterruptTime())&0x1E) | 0x40;
        memcpy(&quic[1], &buffer->KeyIdx, 3);
    }
    else
    {
        ((UINT32 *)buffer)[0] = (UINT32)KeQueryInterruptTime();
        quic[0] = (((UINT32 *)buffer)[0]&0x1E) | 0x41;
        hlen = ((UINT8)KeQueryInterruptTime())&HIDDEN_NOIZE;
        if (hlen > 1) CryptoRandom(quic+sizeof(struct QUIC_data)+1, hlen-1);
        else hlen = 1;
        quic[sizeof(struct QUIC_data)] = (UINT8)MASK_HLEN(hlen, peer->Handshake.RemoteStatic);
        memcpy(((struct QUIC_data *)quic)->DCID, &buffer->KeyIdx, 3);
        hlen += sizeof(struct QUIC_data);
    }

    xor_data((UINT8 *)buffer, (UINT32 *)peer->Handshake.RemoteStatic);
    XOR_HEAD(quic, peer->Handshake.RemoteStatic);

    return hlen;
}

BOOLEAN IsKeepaliveNbOut(NET_BUFFER *nb)
{
    if (NET_BUFFER_DATA_LENGTH(nb) == MessageDataLen(0)) return TRUE;
    UINT8 *buffer = MemGetValidatedNetBufferData(nb);
    return ((buffer[0] & 0x41) == 0x41) && ((buffer[0] & 0x80) == 0);
}

