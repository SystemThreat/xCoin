# Copyright (c) 2023-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(create_test_config)
  set(abs_top_srcdir ${PROJECT_SOURCE_DIR})
  set(abs_top_builddir ${PROJECT_BINARY_DIR})
  set(EXEEXT ${CMAKE_EXECUTABLE_SUFFIX})

  macro(set_configure_variable var conf_var)
    if(${var})
      set(${conf_var}_TRUE "")
    else()
      set(${conf_var}_TRUE "#")
    endif()
  endmacro()

  set_configure_variable(ENABLE_WALLET ENABLE_WALLET)
  set_configure_variable(BUILD_BENCH BUILD_BENCH)
  set_configure_variable(BUILD_CLI BUILD_BITCOIN_CLI)
  set_configure_variable(BUILD_TX BUILD_BITCOIN_TX)
  set_configure_variable(BUILD_UTIL BUILD_BITCOIN_UTIL)
  set_configure_variable(BUILD_UTIL_CHAINSTATE BUILD_BITCOIN_CHAINSTATE)
  set_configure_variable(BUILD_WALLET_TOOL BUILD_BITCOIN_WALLET)
  set_configure_variable(BUILD_DAEMON BUILD_BITCOIND)
  set_configure_variable(BUILD_FUZZ_BINARY ENABLE_FUZZ_BINARY)
  set_configure_variable(WITH_ZMQ ENABLE_ZMQ)
  set_configure_variable(WITH_EMBEDDED_ASMAP ENABLE_EMBEDDED_ASMAP)
  set_configure_variable(ENABLE_EXTERNAL_SIGNER ENABLE_EXTERNAL_SIGNER)
  set_configure_variable(WITH_USDT ENABLE_USDT_TRACEPOINTS)
  set_configure_variable(ENABLE_IPC ENABLE_IPC)

  configure_file(config.ini.in config.ini USE_SOURCE_PERMISSIONS @ONLY)
endfunction()

create_test_config()


function(create_test_directory_links)
  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/functional)
  file(GLOB functional
    LIST_DIRECTORIES FALSE
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    functional/*.html
    functional/*.py
  )

  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/functional/data)
  file(GLOB functional_data
    LIST_DIRECTORIES FALSE
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    functional/data/*.json
    functional/data/*.py
  )

  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/functional/mocks)
  file(GLOB functional_mocks
    LIST_DIRECTORIES FALSE
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    functional/mocks/*.py
  )

  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/functional/test_framework)
  file(GLOB functional_test_framework
    LIST_DIRECTORIES FALSE
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    functional/test_framework/*.csv
    functional/test_framework/*.py
  )

  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/functional/test_framework/crypto)
  file(GLOB functional_test_framework_crypto
    LIST_DIRECTORIES FALSE
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    functional/test_framework/crypto/*.csv
    functional/test_framework/crypto/*.py
  )

  file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/fuzz)
  set(files_to_link
    ${functional}
    ${functional_data}
    ${functional_mocks}
    ${functional_test_framework}
    ${functional_test_framework_crypto}
    fuzz/test_runner.py
  )

  foreach(f IN LISTS files_to_link)
    if(CMAKE_HOST_WIN32)
      set(symlink)
    else()
      set(symlink SYMBOLIC)
    endif()
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/${f} ${CMAKE_CURRENT_BINARY_DIR}/${f} COPY_ON_ERROR ${symlink})
  endforeach()
endfunction()

create_test_directory_links()

# xCoin: the emission table in src/consensus/params.h is generated from
# contrib/regenesis/emission-policy.json. emission_policy_check_params fails when the
# policy changed without regeneration, the rows were edited by hand, MAX_SUPPLY_SAT or
# MAX_MONEY disagree with the cap, or charter section 4's PROVISIONAL comment disagrees
# with the policy status, or the generated rows differ byte for byte from
# contrib/regenesis/emission-rows.txt (the table whose SHA-256 charter section 4
# states). emission_shape_spots fails when a line carrying the
# emission-shape grep tag is added or removed without updating
# contrib/regenesis/EMISSION-SHAPE-SPOTS.md (which names the tag).
if(BUILD_TESTS AND Python3_EXECUTABLE)
  add_test(NAME emission_policy_check_params
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/contrib/regenesis/emission.py --check-params --quiet
            --rows ${PROJECT_SOURCE_DIR}/contrib/regenesis/emission-rows.txt
  )
  add_test(NAME emission_shape_spots
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/contrib/regenesis/emission.py --check-spots
  )
endif()
