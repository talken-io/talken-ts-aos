/******************************************************************************
 * TrustSigner Library (BTC,ETH,XLM Keypair/Signature Maker)
 *
 * Description : White-box encryption header
 *
 * Copyright (C) 2018-2019 NexL Corporation. All rights reserved.
 * http://www.nexl.kr (myseo@nexl.kr)
 ******************************************************************************
 * Edit History
 * When            Who         What, Where, Why
 * 2018/12/20      myseo       create.
 ******************************************************************************/

#ifndef TRUST_SINER_WHITEBOC_H
#define TRUST_SINER_WHITEBOC_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if defined(__LINUX__)
#define WB_TABLE_LENGTH			1275881 // magic number
#elif defined(__aarch64__)
#define WB_TABLE_LENGTH			1275881 // magic number // 1275881 // 1107961
#else
#define WB_TABLE_LENGTH			1260549 // magic number
#endif

#define WB_ENCDATA_LENGTH		80 // magic number

#define WB_LEN_BUF_LENGTH		8

int trust_signer_create_table(char **table);
int trust_signer_encrypt(char *table, int table_length, unsigned char *input, int in_length, unsigned char *output, bool encrypt);

#if defined(__cplusplus)
}
#endif

#endif
