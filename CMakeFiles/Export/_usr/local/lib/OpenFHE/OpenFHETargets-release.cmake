#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "OPENFHEcore" for configuration "Release"
set_property(TARGET OPENFHEcore APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(OPENFHEcore PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libOPENFHEcore.so.1.1.4"
  IMPORTED_SONAME_RELEASE "libOPENFHEcore.so.1"
  )

list(APPEND _IMPORT_CHECK_TARGETS OPENFHEcore )
list(APPEND _IMPORT_CHECK_FILES_FOR_OPENFHEcore "${_IMPORT_PREFIX}/lib/libOPENFHEcore.so.1.1.4" )

# Import target "OPENFHEpke" for configuration "Release"
set_property(TARGET OPENFHEpke APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(OPENFHEpke PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libOPENFHEpke.so.1.1.4"
  IMPORTED_SONAME_RELEASE "libOPENFHEpke.so.1"
  )

list(APPEND _IMPORT_CHECK_TARGETS OPENFHEpke )
list(APPEND _IMPORT_CHECK_FILES_FOR_OPENFHEpke "${_IMPORT_PREFIX}/lib/libOPENFHEpke.so.1.1.4" )

# Import target "OPENFHEbinfhe" for configuration "Release"
set_property(TARGET OPENFHEbinfhe APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(OPENFHEbinfhe PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libOPENFHEbinfhe.so.1.1.4"
  IMPORTED_SONAME_RELEASE "libOPENFHEbinfhe.so.1"
  )

list(APPEND _IMPORT_CHECK_TARGETS OPENFHEbinfhe )
list(APPEND _IMPORT_CHECK_FILES_FOR_OPENFHEbinfhe "${_IMPORT_PREFIX}/lib/libOPENFHEbinfhe.so.1.1.4" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
