#pragma once

#include "messages.h"
#include "arithmetic.h"

#define HEADER_TYPE_HIDDEN(Header) ((UINT8)Le32ToCpu((Header)->Type) % 7)

#define NBL_TYPE_HIDDEN(Nbl) HEADER_TYPE_HIDDEN((MESSAGE_HEADER *)MemGetValidatedNetBufferListData(Nbl))


UINT32_LE HiddenType(enum MESSAGE_TYPE);