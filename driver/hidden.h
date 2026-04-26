#pragma once

#include "messages.h"
#include "arithmetic.h"

#define HEADER_TYPE_HIDDEN(Header) ((UINT8)((Header)->Type))
//#define HEADER_TYPE_HIDDEN(Header) (((UINT8)(Header)->Type)%7)
#define NBL_TYPE_HIDDEN(Nbl) HEADER_TYPE_HIDDEN((MESSAGE_HEADER *)MemGetValidatedNetBufferListData(Nbl))
//#define NBL_TYPE_HIDDEN(Nbl) (((UINT8)((MESSAGE_HEADER *)MemGetValidatedNetBufferListData(Nbl))->Type)%7)


UINT32_LE HiddenType(enum MESSAGE_TYPE);