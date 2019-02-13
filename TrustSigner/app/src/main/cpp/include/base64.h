/******************************************************************************
 * TrustSigner Library (BTC,ETH,XLM Keypair/Signature Maker)
 *
 * Description : Base64 Header
 *
 * Copyright (C) 2018-2019 NexL Corporation. All rights reserved.
 * http://www.nexl.kr (myseo@nexl.kr)
 ******************************************************************************
 * Edit History
 * When            Who         What, Where, Why
 * 2019/02/02      myseo       create.
 ******************************************************************************/

#ifndef TRUSTSIGNER_BASE64_H
#define TRUSTSIGNER_BASE64_H

#include <stdio.h>
#include <stdlib.h>

char *base64_encode(const char *in, size_t size);
char *base64_decode(const char *in);

#endif //TRUSTSIGNER_BASE64_H
