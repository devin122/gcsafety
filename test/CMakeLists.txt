configure_lit_site_cfg(
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.py.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg.py
  MAIN_CONFIG
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.cfg.py
)

 set(LLVM_EXTERNAL_LIT "${CMAKE_SOURCE_DIR}/extern/lit/lit.py")

add_lit_testsuite(check-gcsafety "Running the Clang extra tools' regression tests"
  ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS not
  ARGS ${CLANG_TOOLS_TEST_EXTRA_ARGS}
)