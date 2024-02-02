# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

set (PLATFORM_SHARED_DIR ${CMAKE_CURRENT_LIST_DIR})

if(WIN32)
  add_definitions(-DBH_PLATFORM_WIN_SGX)
else()
  add_definitions(-DBH_PLATFORM_LINUX_SGX)
endif()

include_directories(${PLATFORM_SHARED_DIR})
include_directories(${PLATFORM_SHARED_DIR}/../include)

if(WIN32)
  if ("$ENV{SGXSDKInstallPath}" STREQUAL "")
    set (SGX_SDK_DIR "C:/Program Files (x86)/Intel/IntelSGXSDK")
  else()
    set (SGX_SDK_DIR $ENV{SGXSDKInstallPath})
  endif()
else()
  if ("$ENV{SGX_SDK}" STREQUAL "")
    set (SGX_SDK_DIR "/opt/intel/sgxsdk")
  else()
    set (SGX_SDK_DIR $ENV{SGX_SDK})
  endif()
endif()

include_directories (${SGX_SDK_DIR}/include)
if(WIN32)
  if (NOT BUILD_UNTRUST_PART EQUAL 1)
    include_directories (${SGX_SDK_DIR}/include/tlibc
                        ${SGX_SDK_DIR}/include/libc++)
  endif ()
else()
  if (NOT BUILD_UNTRUST_PART EQUAL 1)
    include_directories (${SGX_SDK_DIR}/include/tlibc
                        ${SGX_SDK_DIR}/include/libcxx)
  endif ()
endif()

if (NOT WAMR_BUILD_LIBC_WASI EQUAL 1)
  add_definitions(-DSGX_DISABLE_WASI)
endif ()

if (NOT WAMR_BUILD_THREAD_MGR EQUAL 1)
  add_definitions(-DSGX_DISABLE_PTHREAD)
endif ()

file (GLOB source_all ${PLATFORM_SHARED_DIR}/*.[c|cpp])

set (PLATFORM_SHARED_SOURCE ${source_all})
