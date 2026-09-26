# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

include(AddWindowsResources)

configure_file(${PROJECT_SOURCE_DIR}/cmake/bitcoin-build-config.h.in bitcoin-build-config.h USE_SOURCE_PERMISSIONS @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

#=============================
# Subprojects
#=============================
# Subprojects include subdirectories that do or could have tests
# and/or benchmark binaries, such as all subtrees and univalue.
# These need to be included before CMAKE_*_OUTPUT_DIRECTORY variables
# are set, so output locations of subproject tests and libraries are
# not overridden.
include(../cmake/crc32c.cmake)
include(../cmake/leveldb.cmake)
include(../cmake/minisketch.cmake)
add_subdirectory(univalue)
if (ENABLE_IPC AND NOT WITH_EXTERNAL_LIBMULTIPROCESS)
  include(../cmake/libmultiprocess.cmake)
  add_libmultiprocess(ipc/libmultiprocess)
endif()
include(../cmake/secp256k1.cmake)
add_secp256k1(secp256k1)

#=============================
# Post-quantum signatures: ML-DSA-65 (FIPS 204) and SLH-DSA-SHA2-128s
# (FIPS 205; PQClean sphincs-sha2-128s-simple, see pqcrypto/slh-dsa-sha2-128s/PQCLEAN)
# Vendored PQClean code with local modifications; the provenance records are
# pqcrypto/ml-dsa-65/PQCLEAN and pqcrypto/slh-dsa-sha2-128s/PQCLEAN.
#=============================
add_library(pqcrypto STATIC
  pqcrypto/common/cleanse.c
  pqcrypto/common/fips202.c
  pqcrypto/common/sha2.c
  pqcrypto/ml-dsa-65/ntt.c
  pqcrypto/ml-dsa-65/packing.c
  pqcrypto/ml-dsa-65/poly.c
  pqcrypto/ml-dsa-65/polyvec.c
  pqcrypto/ml-dsa-65/reduce.c
  pqcrypto/ml-dsa-65/rounding.c
  pqcrypto/ml-dsa-65/sign.c
  pqcrypto/ml-dsa-65/symmetric-shake.c
  pqcrypto/slh-dsa-sha2-128s/address.c
  pqcrypto/slh-dsa-sha2-128s/context_sha2.c
  pqcrypto/slh-dsa-sha2-128s/fors.c
  pqcrypto/slh-dsa-sha2-128s/hash_sha2.c
  pqcrypto/slh-dsa-sha2-128s/merkle.c
  pqcrypto/slh-dsa-sha2-128s/sign.c
  pqcrypto/slh-dsa-sha2-128s/thash_sha2_simple.c
  pqcrypto/slh-dsa-sha2-128s/utils.c
  pqcrypto/slh-dsa-sha2-128s/utilsx1.c
  pqcrypto/slh-dsa-sha2-128s/wots.c
  pqcrypto/slh-dsa-sha2-128s/wotsx1.c
)
# The SLH-DSA directory is deliberately NOT an include directory: its hash.h/utils.h/api.h
# would shadow Bitcoin's; its files use quote-includes, and consumers include
# <pqcrypto/slh-dsa-sha2-128s/api.h> by full path.
target_include_directories(pqcrypto PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/pqcrypto/common
  ${CMAKE_CURRENT_SOURCE_DIR}/pqcrypto/ml-dsa-65
)
# PQClean's randombytes.c (a direct OS RNG call) is deliberately not built:
# PQCLEAN_randombytes is provided by pqrandom.cpp in bitcoin_util and routes
# through the node's GetStrongRandBytes. The edge is declared here so that every
# consumer of pqcrypto links bitcoin_util after it (GNU ld needs the order).
# sanitize_interface carries the -fsanitize flags, which apply to C as they do
# to C++, so a sanitizer or fuzzing build instruments the vendored code too.
target_link_libraries(pqcrypto
  PRIVATE
    sanitize_interface
    bitcoin_util
)

# The vendored C parses attacker-supplied keys and signatures in consensus
# (PQClean) or handshake data from any peer (mlkem-native, below), so it gets
# the same hardening as the C++ (the core_interface block in the top-level
# CMakeLists.txt), checked against the C compiler here because
# core_interface's flags were probed with the C++ compiler. Warnings are each
# upstream's own set (their Makefiles build with -Werror under these flags),
# not suppressed: every warning that appears in these sources is a bug or a
# documented local change.
include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
function(vendored_c_try_append_flag target flag)
  string(MAKE_C_IDENTIFIER "${flag}" id_string)
  string(TOUPPER "${id_string}" id_string)
  set(CMAKE_REQUIRED_FLAGS "-Werror")
  check_c_compiler_flag("${flag}" C_SUPPORTS_${id_string})
  if(C_SUPPORTS_${id_string})
    target_compile_options(${target} PRIVATE ${flag})
  endif()
endfunction()
# The warning flags given after the target, then the hardening flags.
function(vendored_c_compile_options target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W3)
    return()
  endif()
  foreach(flag IN LISTS ARGN)
    vendored_c_try_append_flag(${target} ${flag})
  endforeach()

  # _FORTIFY_SOURCE requires that there is some level of optimization,
  # otherwise it does nothing and just creates a compiler warning.
  set(CMAKE_REQUIRED_FLAGS "-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -Werror")
  check_c_source_compiles("int main(void) {
    #if !defined __OPTIMIZE__ || __OPTIMIZE__ <= 0
      #error
    #endif
    return 0;
  }" C_SUPPORTS_FORTIFY_SOURCE)
  if(C_SUPPORTS_FORTIFY_SOURCE)
    target_compile_options(${target} PRIVATE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
  endif()
  unset(CMAKE_REQUIRED_FLAGS)

  # See the notes on -fstack-reuse=none (GCC bug 111843) in the top-level CMakeLists.txt.
  vendored_c_try_append_flag(${target} -fstack-reuse=none)
  vendored_c_try_append_flag(${target} -Wstack-protector)
  vendored_c_try_append_flag(${target} -fstack-protector-all)
  vendored_c_try_append_flag(${target} -fcf-protection=full)
  if(NOT MINGW)
    # stack-clash-protection is a no-op for Windows (GCC bug 90458).
    vendored_c_try_append_flag(${target} -fstack-clash-protection)
  endif()
  if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
      vendored_c_try_append_flag(${target} -mbranch-protection=bti)
    else()
      vendored_c_try_append_flag(${target} -mbranch-protection=standard)
    endif()
  endif()
endfunction()
# PQClean's own warning set minus -Wvla: the SLH-DSA sources use the
# PQCLEAN_VLA macro on purpose, with sizes bounded by compile-time parameters
# (tree heights, WOTS chain counts, seed lengths), so those six warnings are
# not actionable; see pqcrypto/slh-dsa-sha2-128s/PQCLEAN.
vendored_c_compile_options(pqcrypto
  -Wall -Wextra -Wpedantic -Wshadow -Wmissing-prototypes -Wredundant-decls -Wcast-align -Wpointer-arith -Wundef
)

#=============================
# ML-KEM-768 (FIPS 203) for the hybrid v2 transport (XIP-4, HX1): vendored
# mlkem-native, portable C, built as the one compilation unit
# crypto/mlkem-native/mlkem768.c with crypto/mlkem-native/xcoin_config.h.
# The provenance record is crypto/mlkem-native/PINNED; the C++ interface is
# crypto/mlkem768.h (bitcoin_common).
#=============================
add_library(mlkem_native STATIC
  crypto/mlkem-native/mlkem768.c
)
# No include directory is added: some of mlkem-native's header names (params.h,
# poly.h, symmetric.h) are also pqcrypto/ml-dsa-65's, which is a public include
# directory of pqcrypto. The sources use quote-includes, and crypto/mlkem768.cpp
# includes the public header by full path.
# The randombytes and zeroize hooks are in pqrandom.cpp (bitcoin_util).
target_link_libraries(mlkem_native
  PRIVATE
    sanitize_interface
    bitcoin_util
)
# mlkem-native's own warning set (test/mk/config.mk) plus the ones PQClean's
# adds (-Wcast-align, -Wundef) and -Wvla.
vendored_c_compile_options(mlkem_native
  -Wall -Wextra -Wpedantic -Wshadow -Wmissing-prototypes -Wredundant-decls -Wcast-align -Wpointer-arith -Wundef
  -Wvla -Wconversion -Wsign-conversion
)

# Set top-level target output locations.
if(NOT CMAKE_RUNTIME_OUTPUT_DIRECTORY)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
endif()
if(NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()
if(NOT CMAKE_ARCHIVE_OUTPUT_DIRECTORY)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
endif()

add_custom_target(generate_build_info
  BYPRODUCTS ${PROJECT_BINARY_DIR}/src/bitcoin-build-info.h
  COMMAND ${CMAKE_COMMAND} -DBUILD_INFO_HEADER_PATH=${PROJECT_BINARY_DIR}/src/bitcoin-build-info.h -DSOURCE_DIR=${PROJECT_SOURCE_DIR} -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateBuildInfo.cmake
  COMMENT "Generating bitcoin-build-info.h"
  VERBATIM
)
add_library(bitcoin_clientversion STATIC
  clientversion.cpp
)
target_link_libraries(bitcoin_clientversion
  PRIVATE
    core_interface
)
add_dependencies(bitcoin_clientversion generate_build_info)

add_subdirectory(crypto)
add_subdirectory(util)
if(ENABLE_IPC)
  add_subdirectory(ipc)
endif()

# The charter (contrib/regenesis/CHARTER.md) is embedded byte for byte: the
# node prints CURRENCY_ID = SHA-256(genesis header || charter text) and the
# unit suite recomputes Consensus::CHARTER_HASH from it (REGENESIS.md section 1).
# Regenerated whenever the charter changes, so an edit fails the tests.
set(charter_text_header ${CMAKE_CURRENT_BINARY_DIR}/consensus/charter_text.h)
add_custom_command(
  OUTPUT ${charter_text_header}
  COMMAND ${CMAKE_COMMAND} -DRAW_SOURCE_PATH=${PROJECT_SOURCE_DIR}/contrib/regenesis/CHARTER.md -DHEADER_PATH=${charter_text_header} -DRAW_NAMESPACE=xat::charter_text -P ${PROJECT_SOURCE_DIR}/cmake/script/GenerateHeaderFromRaw.cmake
  DEPENDS ${PROJECT_SOURCE_DIR}/contrib/regenesis/CHARTER.md ${PROJECT_SOURCE_DIR}/cmake/script/GenerateHeaderFromRaw.cmake
  COMMENT "Embedding contrib/regenesis/CHARTER.md"
  VERBATIM
)

add_library(bitcoin_consensus STATIC EXCLUDE_FROM_ALL
  arith_uint256.cpp
  consensus/charter.cpp
  consensus/merkle.cpp
  consensus/tx_check.cpp
  hash.cpp
  pqkey.cpp
  primitives/block.cpp
  primitives/transaction.cpp
  pubkey.cpp
  script/interpreter.cpp
  script/script.cpp
  script/script_error.cpp
  script/solver.cpp
  slhkey.cpp
  uint256.cpp
)
target_sources(bitcoin_consensus PRIVATE ${charter_text_header})
target_link_libraries(bitcoin_consensus
  PRIVATE
    core_interface
    bitcoin_crypto
    bitcoin_util # slhkey.cpp's key generation uses GetStrongRandBytes; GNU ld needs the edge declared
    pqcrypto
    secp256k1
)

if(WITH_ZMQ)
  add_subdirectory(zmq)
endif()

# Home for common functionality shared by different executables and libraries.
# Similar to `bitcoin_util` library, but higher-level.
add_library(bitcoin_common STATIC EXCLUDE_FROM_ALL
  addresstype.cpp
  base58.cpp
  bech32.cpp
  chain.cpp
  chainparams.cpp
  chainparamsbase.cpp
  coins.cpp
  common/args.cpp
  common/bloom.cpp
  common/config.cpp
  common/init.cpp
  common/interfaces.cpp
  common/messages.cpp
  common/netif.cpp
  common/pcp.cpp
  common/run_command.cpp
  common/settings.cpp
  common/signmessage.cpp
  common/system.cpp
  common/url.cpp
  compressor.cpp
  core_io.cpp
  crypto/mlkem768.cpp
  deploymentinfo.cpp
  external_signer.cpp
  init/common.cpp
  kernel/chainparams.cpp
  key.cpp
  key_io.cpp
  pqhd.cpp
  metaldag/metaldag.cpp
  merkleblock.cpp
  musig.cpp
  net_permissions.cpp
  net_types.cpp
  netaddress.cpp
  netbase.cpp
  outputtype.cpp
  policy/feerate.cpp
  policy/policy.cpp
  pow.cpp
  protocol.cpp
  psbt.cpp
  rpc/rawtransaction_util.cpp
  rpc/request.cpp
  rpc/util.cpp
  scheduler.cpp
  script/descriptor.cpp
  script/miniscript.cpp
  script/parsing.cpp
  script/sign.cpp
  script/signingprovider.cpp
)
target_link_libraries(bitcoin_common
  PRIVATE
    core_interface
    bitcoin_consensus
    bitcoin_util
    univalue
    mlkem_native
    pqcrypto
    secp256k1
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
    $<$<PLATFORM_ID:Windows>:ws2_32>
)

include(InstallBinaryComponent)

if(ENABLE_WALLET)
  add_subdirectory(wallet)

  if(BUILD_WALLET_TOOL)
    add_executable(bitcoin-wallet
      bitcoin-wallet.cpp
      init/bitcoin-wallet.cpp
      wallet/wallettool.cpp
    )
    add_windows_resources(bitcoin-wallet bitcoin-wallet-res.rc)
    add_windows_application_manifest(bitcoin-wallet)
    target_link_libraries(bitcoin-wallet
      core_interface
      bitcoin_wallet
      bitcoin_common
      bitcoin_util
      Boost::headers
    )
    set_target_properties(bitcoin-wallet PROPERTIES OUTPUT_NAME nex-wallet)
    install_binary_component(bitcoin-wallet HAS_MANPAGE)
  endif()
endif()


# P2P and RPC server functionality used by `bitcoind` and `bitcoin-qt` executables.
add_library(bitcoin_node STATIC EXCLUDE_FROM_ALL
  addrdb.cpp
  addrman.cpp
  banman.cpp
  bip324.cpp
  blockencodings.cpp
  blockfilter.cpp
  consensus/tx_verify.cpp
  dbwrapper.cpp
  deploymentstatus.cpp
  flatfile.cpp
  headerssync.cpp
  httprpc.cpp
  httpserver.cpp
  i2p.cpp
  index/base.cpp
  index/blockfilterindex.cpp
  index/coinstatsindex.cpp
  index/txindex.cpp
  index/txospenderindex.cpp
  init.cpp
  kernel/chain.cpp
  kernel/checks.cpp
  kernel/coinstats.cpp
  kernel/context.cpp
  kernel/cs_main.cpp
  kernel/disconnected_transactions.cpp
  kernel/mempool_removal_reason.cpp
  mapport.cpp
  net.cpp
  net_processing.cpp
  netgroup.cpp
  node/abort.cpp
  node/blockmanager_args.cpp
  node/blockstorage.cpp
  node/caches.cpp
  node/chainstate.cpp
  node/chainstatemanager_args.cpp
  node/coin.cpp
  node/coins_view_args.cpp
  node/connection_types.cpp
  node/context.cpp
  node/database_args.cpp
  node/eviction.cpp
  node/interface_ui.cpp
  node/interfaces.cpp
  node/kernel_notifications.cpp
  node/mempool_args.cpp
  node/mempool_persist.cpp
  node/mempool_persist_args.cpp
  node/miner.cpp
  node/mini_miner.cpp
  node/minisketchwrapper.cpp
  node/peerman_args.cpp
  node/psbt.cpp
  node/timeoffsets.cpp
  node/transaction.cpp
  node/txdownloadman_impl.cpp
  node/txorphanage.cpp
  node/txreconciliation.cpp
  node/utxo_snapshot.cpp
  node/warnings.cpp
  noui.cpp
  policy/ephemeral_policy.cpp
  policy/fees/block_policy_estimator.cpp
  policy/fees/block_policy_estimator_args.cpp
  policy/packages.cpp
  policy/rbf.cpp
  policy/settings.cpp
  policy/truc_policy.cpp
  private_broadcast.cpp
  rest.cpp
  rpc/blockchain.cpp
  rpc/external_signer.cpp
  rpc/fees.cpp
  rpc/mempool.cpp
  rpc/mining.cpp
  rpc/net.cpp
  rpc/node.cpp
  rpc/output_script.cpp
  rpc/rawtransaction.cpp
  rpc/server.cpp
  rpc/server_util.cpp
  rpc/signmessage.cpp
  rpc/txoutproof.cpp
  script/sigcache.cpp
  torcontrol.cpp
  txdb.cpp
  txgraph.cpp
  txmempool.cpp
  txrequest.cpp
  validation.cpp
  validationinterface.cpp
  versionbits.cpp
  $<$<TARGET_EXISTS:bitcoin_wallet>:wallet/init.cpp>
  $<$<NOT:$<TARGET_EXISTS:bitcoin_wallet>>:dummywallet.cpp>
)
target_link_libraries(bitcoin_node
  PRIVATE
    core_interface
    bitcoin_common
    bitcoin_util
    $<TARGET_NAME_IF_EXISTS:bitcoin_zmq>
    leveldb
    minisketch
    univalue
    Boost::headers
    $<TARGET_NAME_IF_EXISTS:libevent::core>
    $<TARGET_NAME_IF_EXISTS:libevent::extra>
    $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    $<TARGET_NAME_IF_EXISTS:USDT::headers>
)
if(WITH_EMBEDDED_ASMAP)
  target_compile_definitions(bitcoin_node PRIVATE ENABLE_EMBEDDED_ASMAP=1)
  include(TargetDataSources)
  target_raw_data_sources(bitcoin_node NAMESPACE node::data
    node/data/ip_asn.dat
  )
endif()

# Bitcoin wrapper executable that can call other executables.
if(BUILD_BITCOIN_BIN)
  add_executable(bitcoin bitcoin.cpp)
  set_target_properties(bitcoin PROPERTIES OUTPUT_NAME nex)
  add_windows_resources(bitcoin bitcoin-res.rc)
  add_windows_application_manifest(bitcoin)
  target_link_libraries(bitcoin core_interface bitcoin_common bitcoin_util)
  install_binary_component(bitcoin HAS_MANPAGE)
endif()

# Bitcoin Core bitcoind.
if(BUILD_DAEMON)
  add_executable(bitcoind
    bitcoind.cpp
    init/bitcoind.cpp
  )
  add_windows_resources(bitcoind bitcoind-res.rc)
  add_windows_application_manifest(bitcoind)
  target_link_libraries(bitcoind
    core_interface
    bitcoin_node
    $<TARGET_NAME_IF_EXISTS:bitcoin_wallet>
  )
  set_target_properties(bitcoind PROPERTIES OUTPUT_NAME nexd)
  install_binary_component(bitcoind HAS_MANPAGE)
endif()
if(ENABLE_IPC AND BUILD_DAEMON)
  add_executable(bitcoin-node
    bitcoind.cpp
    init/bitcoin-node.cpp
  )
  target_link_libraries(bitcoin-node
    core_interface
    bitcoin_node
    bitcoin_ipc
    $<TARGET_NAME_IF_EXISTS:bitcoin_wallet>
  )
  install_binary_component(bitcoin-node INTERNAL)
endif()


add_library(bitcoin_cli STATIC EXCLUDE_FROM_ALL
  compat/stdin.cpp
  rpc/client.cpp
)
target_link_libraries(bitcoin_cli
  PUBLIC
    core_interface
    univalue
)


# Bitcoin Core RPC client
if(BUILD_CLI)
  add_executable(bitcoin-cli bitcoin-cli.cpp)
  add_windows_resources(bitcoin-cli bitcoin-cli-res.rc)
  add_windows_application_manifest(bitcoin-cli)
  target_link_libraries(bitcoin-cli
    core_interface
    bitcoin_cli
    bitcoin_common
    bitcoin_util
    libevent::core
    libevent::extra
  )
  set_target_properties(bitcoin-cli PROPERTIES OUTPUT_NAME nex-cli)
  install_binary_component(bitcoin-cli HAS_MANPAGE)
endif()


if(BUILD_TX)
  add_executable(bitcoin-tx bitcoin-tx.cpp)
  add_windows_resources(bitcoin-tx bitcoin-tx-res.rc)
  add_windows_application_manifest(bitcoin-tx)
  target_link_libraries(bitcoin-tx
    core_interface
    bitcoin_common
    bitcoin_util
    univalue
  )
  set_target_properties(bitcoin-tx PROPERTIES OUTPUT_NAME nex-tx)
  install_binary_component(bitcoin-tx HAS_MANPAGE)
endif()


if(BUILD_UTIL)
  add_executable(bitcoin-util bitcoin-util.cpp)
  add_windows_resources(bitcoin-util bitcoin-util-res.rc)
  add_windows_application_manifest(bitcoin-util)
  target_link_libraries(bitcoin-util
    core_interface
    bitcoin_common
    bitcoin_util
  )
  install_binary_component(bitcoin-util HAS_MANPAGE)
endif()

# xCoin v2 genesis miner: builds the charter genesis block and grinds its nonce
# with the node's own MetalDAG verification path (REGENESIS.md sections 1 and 8).
if(BUILD_XCOIN_GENESIS)
  add_executable(xcoin-genesis xcoin-genesis.cpp)
  add_windows_application_manifest(xcoin-genesis)
  target_link_libraries(xcoin-genesis
    core_interface
    bitcoin_common
    bitcoin_util
  )
  install_binary_component(xcoin-genesis)

endif()




if(BUILD_KERNEL_LIB)
  add_subdirectory(kernel)
  target_sources(bitcoinkernel PRIVATE ${charter_text_header})
  if (BUILD_KERNEL_TEST)
    add_subdirectory(test/kernel)
  endif()
  if(BUILD_UTIL_CHAINSTATE)
    add_executable(bitcoin-chainstate
      bitcoin-chainstate.cpp
    )
    add_windows_application_manifest(bitcoin-chainstate)
    target_link_libraries(bitcoin-chainstate
      PRIVATE
        core_interface
        bitcoinkernel
    )
    install_binary_component(bitcoin-chainstate INTERNAL)
  endif()
endif()


add_subdirectory(test/util)
if(BUILD_BENCH)
  add_subdirectory(bench)
endif()

if(BUILD_TESTS)
  add_subdirectory(test)
endif()

if(BUILD_FUZZ_BINARY)
  add_subdirectory(test/fuzz)
endif()
