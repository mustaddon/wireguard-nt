#include "hidden.h"
#include "messages.h"
#include "peerlookup.h"


#define XOR_HEAD(skb, mask) ((UINT8 *)(skb))[0]=(((UINT8 *)(skb))[0]&0xF0)|((((UINT8 *)(skb))[0]^((UINT8 *)(mask))[3])&0x0F)
#define MASK_HLEN(val, mask) ((val)^((UINT8 *)(mask))[7])
#define SKB_HLEN(skb, qlen, mask) ((((UINT8 *)(skb))[0]&1) == 0 ? qlen : qlen + MASK_HLEN(((UINT8 *)(skb))[qlen], mask))


static VOID xor_mac2(VOID *skb, SIZE_T len, UINT32 zero, UINT32 *mask)
{
   UINT32 *ptr = (UINT32 *)((UINT8 *)skb + len - 16);
   ptr[0] ^= zero^mask[4];
   ptr[1] ^= zero^mask[5];
   ptr[2] ^= zero^mask[6];
   ptr[3] ^= zero^mask[7];
}

static VOID xor_init(VOID *skb, UINT32 *mask)
{
   UINT32 *ptr = (UINT32 *)(skb);
   UINT32 zero = ptr[0]^mask[0];
   ptr[1] ^= zero^mask[1];
   xor_mac2(skb, sizeof(MESSAGE_HANDSHAKE_INITIATION), zero, mask);
}

static VOID xor_resp(VOID *skb, UINT32 *mask)
{
   UINT32 *ptr = (UINT32 *)(skb);
   UINT32 zero = ptr[0]^mask[0];
   ptr[1] ^= zero^mask[1];
   ptr[2] ^= zero^mask[2];
   xor_mac2(skb, sizeof(MESSAGE_HANDSHAKE_RESPONSE), zero, mask);
}

static VOID xor_cook(VOID *skb, UINT32 *mask)
{
   UINT32 *ptr = (UINT32 *)(skb);
   UINT32 zero = ptr[0]^mask[0];
   ptr[1] ^= zero^mask[1];
}

static VOID xor_data(VOID *skb, UINT32 *mask)
{
   UINT32 *ptr = (UINT32 *)(skb);
   UINT32 zero = ptr[0]^mask[0];
   ptr[1] ^= zero^mask[1];
   ptr[2] ^= zero^mask[2];
   ptr[3] ^= zero^mask[3];
}

static BOOLEAN CopyFromMdl(MDL *Src, ULONG SrcOffset, UINT8 *Dst, ULONG Len)
{
    //if (Dst == NULL || Src == NULL || Len == 0) return FALSE;

    MDL *currentMdl = Src;
    ULONG bytesLeftToCopy = Len;
    ULONG currentOffset = SrcOffset;
    ULONG dstOffset = 0;

    while (currentMdl != NULL && bytesLeftToCopy > 0)
    {
        ULONG mdlByteCount = MmGetMdlByteCount(currentMdl);

        if (currentOffset >= mdlByteCount) {
            currentOffset -= mdlByteCount;
            currentMdl = currentMdl->Next;
            continue;
        }

        ULONG bytesAvailableInCurrentMdl = mdlByteCount - currentOffset;
        ULONG bytesToCopyThisTime = (bytesLeftToCopy < bytesAvailableInCurrentMdl) ? bytesLeftToCopy : bytesAvailableInCurrentMdl;

        UINT8 *systemAddress = MmGetSystemAddressForMdlSafe(currentMdl, NormalPagePriority | MdlMappingNoExecute | MdlMappingNoWrite);
        if (!systemAddress) return FALSE;

        RtlCopyMemory(Dst + dstOffset, systemAddress + currentOffset, bytesToCopyThisTime);

        bytesLeftToCopy -= bytesToCopyThisTime;
        dstOffset += bytesToCopyThisTime;
        currentOffset = 0;
        currentMdl = currentMdl->Next;
    }

    return (bytesLeftToCopy == 0);
}


_Use_decl_annotations_
BOOLEAN PrepareNetBufferListHidden(NET_BUFFER_LIST *Nbl, WG_DEVICE *wg) 
{
    WSK_BUF *buffer = &NET_BUFFER_LIST_DATAGRAM_INDICATION(Nbl)->Buffer;
    if (buffer->Length < MESSAGE_MINIMUM_LENGTH)
        return FALSE;
    
    UINT8 *data = MemGetValidatedNetBufferListData(Nbl);
    if (!CopyFromMdl(buffer->Mdl, buffer->Offset, data, MESSAGE_MINIMUM_LENGTH))
    //if (!NT_SUCCESS(MemCopyFromMdl(data, buffer->Mdl, buffer->Offset, MESSAGE_MINIMUM_LENGTH)))
        return FALSE;

    XOR_HEAD(data, wg->StaticIdentity.StaticPublic);

    int type;
    ULONG hlen;

#define __add_offset_and_pull_data(len) \
    buffer->Offset += hlen; \
    buffer->Length -= hlen; \
    if (!CopyFromMdl(buffer->Mdl, buffer->Offset, data, len)) return FALSE; \
    //if (!NT_SUCCESS(MemCopyFromMdl(data, buffer->Mdl, buffer->Offset, len))) return FALSE;

#define __add_offset_and_pull_data_synchronized(len) \
    NdisAdvanceNetBufferDataStart(NET_BUFFER_LIST_FIRST_NB(Nbl), hlen, FALSE, NULL); \
    buffer->Offset += hlen; \
    buffer->Length -= hlen; \
    data = MemGetValidatedNetBufferListData(Nbl); \
    if (!data || !CopyFromMdl(buffer->Mdl, buffer->Offset, data, len)) return FALSE; \
    //if (!data || !NT_SUCCESS(MemCopyFromMdl(data, buffer->Mdl, buffer->Offset, len))) return FALSE;


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
            if (buffer->Length != hlen + sizeof(MESSAGE_HANDSHAKE_INITIATION))
                return FALSE;
            __add_offset_and_pull_data(sizeof(MESSAGE_HANDSHAKE_INITIATION));
            xor_init(data, (UINT32 *)wg->StaticIdentity.StaticPublic);
        }
        else if(data[9] != 0)
        {
            type = MESSAGE_TYPE_HANDSHAKE_RESPONSE;
            hlen = SKB_HLEN(data, sizeof(struct QUIC_resp), wg->StaticIdentity.StaticPublic);
            if (buffer->Length != hlen + sizeof(MESSAGE_HANDSHAKE_RESPONSE))
                return FALSE;
            __add_offset_and_pull_data(sizeof(MESSAGE_HANDSHAKE_RESPONSE));
            xor_resp(data, (UINT32 *)wg->StaticIdentity.StaticPublic);
        }
        else 
        {
            type = MESSAGE_TYPE_HANDSHAKE_COOKIE;
            hlen = SKB_HLEN(data, sizeof(struct QUIC_cook), wg->StaticIdentity.StaticPublic);
            if (buffer->Length != hlen + sizeof(MESSAGE_HANDSHAKE_COOKIE))
                return FALSE;
            __add_offset_and_pull_data(sizeof(MESSAGE_HANDSHAKE_COOKIE));
            xor_cook(data, (UINT32 *)wg->StaticIdentity.StaticPublic);
        }
    }

    ((UINT32_LE *)(data))[0] = CpuToLe32(type);

    return TRUE;
}

//#define QUIC_START(flags) \
//    quic->flags = flags; \
//    quic->version = CpuToBe32(1);
//
//#define QUIC_END(data, quic, hlen) \
//    quic->token_len = 0; \
//    quic->data_len = CpuToBe16(0x4000 | (sizeof(*data)+hlen));
//
//#define QUIC_HLEN(quic, hlen, mask) \
//    if (hlen > 0) { \
//        if (hlen > 1) get_random_bytes((UINT8 *)quic+sizeof(*quic)+1, hlen-1); \
//        ((UINT8 *)quic)[sizeof(*quic)]=MASK_HLEN(hlen, mask); }
//
//static VOID add_quick_init(
//    MESSAGE_HANDSHAKE_INITIATION *data, 
//    struct QUIC_init *quic,
//    UINT8 flags,
//    SIZE_T hlen,
//    UINT8 *mask)
//{
//    QUIC_START(flags);
//
//    quic->DCID_len = sizeof(quic->DCID);
//    get_random_bytes(quic->DCID, sizeof(quic->DCID));
//
//    quic->SCID_len = sizeof(quic->SCID);
//    memcpy(quic->SCID, &data->sender_index, sizeof(quic->SCID));
//
//    QUIC_END(data, quic, hlen);
//    QUIC_HLEN(quic, hlen, mask);
//}
//
//static VOID add_quick_resp(
//    MESSAGE_HANDSHAKE_RESPONSE *data, 
//    struct QUIC_resp *quic,
//    UINT8 flags,
//    SIZE_T hlen,
//    UINT8 *mask)
//{
//    QUIC_START(flags);
//
//    quic->DCID_len = sizeof(quic->DCID);
//    memcpy(quic->DCID, &data->receiver_index, sizeof(quic->DCID));
//
//    quic->SCID_len = sizeof(quic->SCID);
//    memcpy(quic->SCID, &data->sender_index, sizeof(quic->SCID));
//
//    QUIC_END(data, quic, hlen);
//    QUIC_HLEN(quic, hlen, mask);
//}
//
//static VOID add_quick_cook(
//    MESSAGE_HANDSHAKE_COOKIE *data, 
//    struct QUIC_cook *quic,
//    UINT8 flags,
//    SIZE_T hlen,
//    UINT8 *mask)
//{
//    QUIC_START(flags);
//
//    quic->DCID_len = sizeof(quic->DCID);
//    memcpy(quic->DCID, &data->receiver_index, sizeof(quic->DCID));
//
//    quic->SCID_len = 0;
//
//    QUIC_END(data, quic, hlen);
//    QUIC_HLEN(quic, hlen, mask);
//}
//
//VOID skb_push_hidden_handshake(VOID *skb, VOID *buffer, WG_PEER *peer)
//{
//    UINT8 *quic;
//    UINT8 type = ((UINT8 *)buffer)[0];
//    UINT8 flags;
//    SIZE_T hlen;
//    
//    get_random_bytes(buffer, sizeof(UINT32));
//    hlen = ((UINT8 *)buffer)[0]&HIDDEN_NOIZE;
//    flags = (hlen>0 ? 0xC1 : 0xC0) | (((UINT8 *)buffer)[1]&0x0E);
//    
//    switch (type) {
//        case MESSAGE_TYPE_HANDSHAKE_INITIATION:
//            quic = (UINT8 *)skb_push(skb, sizeof(struct QUIC_init) + hlen);
//            add_quick_init(
//                (MESSAGE_HANDSHAKE_INITIATION *)buffer,
//                (struct QUIC_init *)quic, 
//                flags, hlen, peer->Handshake.RemoteStatic);
//            xor_init(buffer, (UINT32 *)peer->Handshake.RemoteStatic);
//            break;
//
//        case MESSAGE_TYPE_HANDSHAKE_RESPONSE:
//            quic = (UINT8 *)skb_push(skb, sizeof(struct QUIC_resp) + hlen);
//            add_quick_resp(
//                (MESSAGE_HANDSHAKE_RESPONSE *)buffer,
//                (struct QUIC_resp *)quic, 
//                flags, hlen, peer->Handshake.RemoteStatic);
//            xor_resp(buffer, (UINT32 *)peer->Handshake.RemoteStatic);
//            break;
//
//        case MESSAGE_TYPE_HANDSHAKE_COOKIE:
//            quic = (UINT8 *)skb_push(skb, sizeof(struct QUIC_cook) + hlen);
//            add_quick_cook(
//                (MESSAGE_HANDSHAKE_COOKIE *)buffer,
//                (struct QUIC_cook *)quic, 
//                flags, hlen, peer->Handshake.RemoteStatic);
//            xor_cook(buffer, (UINT32 *)peer->Handshake.RemoteStatic);
//            break;
//    }
//
//    XOR_HEAD(quic, peer->Handshake.RemoteStatic);
//}
//
//VOID skb_push_hidden_handshake_cookie(VOID *skb, VOID *buffer, WG_DEVICE *wg)
//{
//    WG_PEER *peer = NULL;
//
//	if (unlikely(!IndexHashtableLookup(wg->IndexHashtable,
//            INDEX_HASHTABLE_HANDSHAKE | INDEX_HASHTABLE_KEYPAIR,
//            ((MESSAGE_HANDSHAKE_COOKIE *)buffer)->receiver_index, &peer)))
//		return;
//    
//    skb_push_hidden_handshake(skb, buffer, peer);
//}
//
//UINT32 hidden_data_header_len(UINT32 len)
//{
//    if (unlikely(len == 32)) 
//    {
//        UINT8 hlen = ((UINT8)ktime_get_coarse_boottime_ns())&HIDDEN_NOIZE;
//        if (hlen > 0) return sizeof(struct QUIC_data) + hlen;
//    }
//    return 0;
//}
//
//VOID skb_push_hidden_data(VOID *skb, VOID *buffer, UINT32 hlen, WG_PEER *peer)
//{
//    UINT8 *quic = (UINT8 *)buffer;
//
//    if (likely(hlen == 0)) 
//    {
//        quic[0] = (((UINT8)ktime_get_coarse_boottime_ns())&0x1E) | 0x40;
//        memcpy(&quic[1], &((MESSAGE_DATA *)buffer)->key_idx, 3);
//    }
//    else
//    {
//        quic = (UINT8 *)skb_push(skb, hlen);
//        ((UINT32 *)buffer)[0] = ktime_get_coarse_boottime_ns();
//        quic[0] = (((UINT32 *)buffer)[0]&0x1E) | 0x41;
//        hlen -= sizeof(struct QUIC_data);
//        if (hlen > 1) get_random_bytes(quic+sizeof(struct QUIC_data)+1, hlen-1);
//        quic[sizeof(struct QUIC_data)] = MASK_HLEN(hlen, peer->Handshake.RemoteStatic);
//        memcpy(((struct QUIC_data *)quic)->DCID, &((MESSAGE_DATA *)buffer)->key_idx, 3);
//    }
//
//    xor_data(buffer, (UINT32 *)peer->Handshake.RemoteStatic);
//    XOR_HEAD(quic, peer->Handshake.RemoteStatic);
//}
