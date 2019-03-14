# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)


add_library(
        trustsigner
        SHARED
        src/main/cpp/bip32_bip39/bignum.c
        src/main/cpp/bip32_bip39/ecdsa.c
        src/main/cpp/bip32_bip39/curves.c
        src/main/cpp/bip32_bip39/secp256k1.c
        src/main/cpp/bip32_bip39/nist256p1.c
        src/main/cpp/bip32_bip39/rand.c
        src/main/cpp/bip32_bip39/hmac.c
        src/main/cpp/bip32_bip39/bip32.c
        src/main/cpp/bip32_bip39/bip39.c
        src/main/cpp/bip32_bip39/bip32_bip39.c
        src/main/cpp/bip32_bip39/pbkdf2.c
        src/main/cpp/bip32_bip39/base58.c
        src/main/cpp/bip32_bip39/base32.c
        src/main/cpp/bip32_bip39/address.c
        src/main/cpp/bip32_bip39/script.c
        src/main/cpp/bip32_bip39/ripemd160.c
        src/main/cpp/bip32_bip39/sha2.c
        src/main/cpp/bip32_bip39/sha3.c
        src/main/cpp/bip32_bip39/hasher.c
        src/main/cpp/bip32_bip39/aes/aescrypt.c
        src/main/cpp/bip32_bip39/aes/aeskey.c
        src/main/cpp/bip32_bip39/aes/aestab.c
        src/main/cpp/bip32_bip39/aes/aes_modes.c
        src/main/cpp/bip32_bip39/ed25519-donna/curve25519-donna-32bit.c
        src/main/cpp/bip32_bip39/ed25519-donna/curve25519-donna-helpers.c
        src/main/cpp/bip32_bip39/ed25519-donna/modm-donna-32bit.c
        src/main/cpp/bip32_bip39/ed25519-donna/ed25519-donna-impl-base.c
        src/main/cpp/bip32_bip39/ed25519-donna/ed25519-donna-basepoint-table.c
        src/main/cpp/bip32_bip39/ed25519-donna/ed25519-donna-32bit-tables.c
        src/main/cpp/bip32_bip39/ed25519-donna/curve25519-donna-scalarmult-base.c
        src/main/cpp/bip32_bip39/ed25519-donna/ed25519.c
        src/main/cpp/bip32_bip39/ed25519-donna/ed25519-sha3.c
        src/main/cpp/bip32_bip39/blake256.c
        src/main/cpp/bip32_bip39/blake2b.c
        src/main/cpp/bip32_bip39/blake2s.c
        src/main/cpp/bip32_bip39/groestl.c
        src/main/cpp/bip32_bip39/memzero.c
        src/main/cpp/whitebox/base.cpp
        src/main/cpp/whitebox/BGEAttack.cpp
        src/main/cpp/whitebox/GenericAES.cpp
        src/main/cpp/whitebox/LinearAffineEq.cpp
        src/main/cpp/whitebox/md5.cpp
        src/main/cpp/whitebox/MixingBijections.cpp
        src/main/cpp/whitebox/NTLUtils.cpp
        src/main/cpp/whitebox/WBAES.cpp
        src/main/cpp/whitebox/WBAESGenerator.cpp
        src/main/cpp/whitebox/RingBuffer.cpp
        src/main/cpp/whitebox/EncTools.cpp
        src/main/cpp/whitebox/InputObject.cpp
        src/main/cpp/whitebox/InputObjectBuffer.cpp
        src/main/cpp/whitebox/InputObjectIstream.cpp
        src/main/cpp/whitebox/InputObjectOstream.cpp
        src/main/cpp/whitebox/InputObjectIOstream.cpp
        src/main/cpp/coin.c
        src/main/cpp/whitebox.cpp
        src/main/cpp/base64.cpp
        src/main/cpp/trustsigner.cpp)

#src/main/cpp/bip32_bip39/ed25519-donna/ed25519-keccak.c
#src/main/cpp/bip32_bip39/nem.c

add_library(ntl STATIC IMPORTED)
set_target_properties(
        ntl
        PROPERTIES
        IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/prebuilt_libs/lib/${ANDROID_ABI}/libntl.a)

add_library(boost_program_options STATIC IMPORTED)
set_target_properties(
        boost_program_options
        PROPERTIES
        IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/prebuilt_libs/lib/${ANDROID_ABI}/libboost_program_options.a)

add_library(boost_serialization STATIC IMPORTED)
set_target_properties(
        boost_serialization
        PROPERTIES
        IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/prebuilt_libs/lib/${ANDROID_ABI}/libboost_serialization.a)

add_library(boost_iostreams STATIC IMPORTED)
set_target_properties(
        boost_iostreams
        PROPERTIES
        IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/prebuilt_libs/lib/${ANDROID_ABI}/libboost_iostreams.a)

add_library(boost_random STATIC IMPORTED)
set_target_properties(
        boost_random
        PROPERTIES
        IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/prebuilt_libs/lib/${ANDROID_ABI}/libboost_random.a)

add_library(boost_regex STATIC IMPORTED)
set_target_properties(
        boost_regex
        PROPERTIES
        IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/prebuilt_libs/lib/${ANDROID_ABI}/libboost_regex.a)

add_library(boost_system STATIC IMPORTED)
set_target_properties(
        boost_system
        PROPERTIES
        IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/prebuilt_libs/lib/${ANDROID_ABI}/libboost_system.a)

include_directories(src/main/cpp/include/)
include_directories(src/main/cpp/bip32_bip39/)
include_directories(src/main/cpp/bip32_bip39/aes/)
include_directories(src/main/cpp/bip32_bip39/ed25519-donna/)
include_directories(src/main/cpp/whitebox/)
include_directories(prebuilt_libs/include/)

find_library(
        log-lib
        log )

target_link_libraries(
        trustsigner
        ntl
        boost_program_options
        boost_serialization
        boost_iostreams
        boost_random
        boost_regex
        boost_system
        ${log-lib}
)

