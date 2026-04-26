#include "hidden.h"
#include "crypto.h"

#pragma warning(disable : 4244)

UINT32_LE HiddenType(enum MESSAGE_TYPE type) 
{
    UINT32_LE val;
    UINT8 rnd;

    CryptoRandom(&val, sizeof(val));
    
    rnd = ((UINT8)val)%245 + 7;
    //((UINT8 *)&val)[0] = rnd + type - rnd%7;
    ((UINT8 *)&val)[0] = type;
    return val;
}