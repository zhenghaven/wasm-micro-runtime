/*
 * Copyright (C) 2019 Intel Corporation.  All rights reserved.
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#include "platform_api_extension.h"

#include <sgx_thread.h>

int wasm_os_cond_init(korp_cond *cond)
{
    return sgx_thread_cond_init(cond, NULL);
}

int wasm_os_cond_destroy(korp_cond *cond)
{
    return sgx_thread_cond_destroy(cond);
}
