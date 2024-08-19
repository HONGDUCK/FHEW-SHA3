# - Config file for the OpenFHE package
# It defines the following variables
#  OpenFHE_INCLUDE_DIRS - include directories for OpenFHE
#  OpenFHE_LIBRARIES    - libraries to link against

get_filename_component(OpenFHE_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)

# Our library dependencies (contains definitions for IMPORTED targets)
if(NOT OpenFHE_BINARY_DIR)
  include("${OpenFHE_CMAKE_DIR}/OpenFHETargets.cmake")
endif()

# These are IMPORTED targets created by OpenFHETargets.cmake
set(OpenFHE_INCLUDE "/usr/local/include/openfhe")
set(OpenFHE_LIBDIR "/usr/local/lib")
set(OpenFHE_LIBRARIES OPENFHEcore;OPENFHEpke;OPENFHEbinfhe  -fopenmp)
set(OpenFHE_STATIC_LIBRARIES   -fopenmp)
set(OpenFHE_SHARED_LIBRARIES OPENFHEcore;OPENFHEpke;OPENFHEbinfhe  -fopenmp)
set(BASE_OPENFHE_VERSION 1.1.4)

set(OPENMP_INCLUDES "" )
set(OPENMP_LIBRARIES "" )

set(OpenFHE_CXX_FLAGS " -Wall -Werror -O3  -DOPENFHE_VERSION=1.1.4 -Wno-parentheses -DMATHBACKEND=4 -fopenmp")
set(OpenFHE_C_FLAGS " -Wall -Werror -O3  -DOPENFHE_VERSION=1.1.4 -DMATHBACKEND=4 -fopenmp")

if( "OFF" STREQUAL "Y" )
	set(OpenFHE_CXX_FLAGS "${OpenFHE_CXX_FLAGS} -DWITH_NTL" )
	set(OpenFHE_C_FLAGS "${OpenFHE_C_FLAGS} -DWITH_NTL")
endif()

set (OpenFHE_EXE_LINKER_FLAGS " ")

# CXX info
set(OpenFHE_CXX_STANDARD "17")
set(OpenFHE_CXX_COMPILER_ID "GNU")
set(OpenFHE_CXX_COMPILER_VERSION "11.4.0")

# Build Options
set(OpenFHE_STATIC "OFF")
set(OpenFHE_SHARED "ON")
set(OpenFHE_TCM "OFF")
set(OpenFHE_OPENMP "ON")
set(OpenFHE_NATIVE_SIZE "32")
set(OpenFHE_CKKS_M_FACTOR "1")
set(OpenFHE_NATIVEOPT "OFF")

# Math Backend
set(OpenFHE_BACKEND "4")

# Build Details
set(OpenFHE_EMSCRIPTEN "")
set(OpenFHE_ARCHITECTURE "x86_64")
set(OpenFHE_BACKEND_FLAGS_BASE "-DMATHBACKEND=4")

# Compile Definitions

if( "ON" )
	set(OpenFHE_BINFHE_COMPILE_DEFINITIONS "_compile_defs-NOTFOUND")
	set(OpenFHE_CORE_COMPILE_DEFINITIONS "_compile_defs-NOTFOUND")
	set(OpenFHE_PKE_COMPILE_DEFINITIONS "_compile_defs-NOTFOUND")
	set(OpenFHE_COMPILE_DEFINITIONS
			${OpenFHE_BINFHE_COMPILE_DEFINITIONS}
			${OpenFHE_CORE_COMPILE_DEFINITIONS}
			${OpenFHE_PKE_COMPILE_DEFINITIONS})
endif()

if( "OFF" )
	set(OpenFHE_BINFHE_COMPILE_DEFINITIONS_STATIC "")
	set(OpenFHE_CORE_COMPILE_DEFINITIONS_STATIC "")
	set(OpenFHE_PKE_COMPILE_DEFINITIONS_STATIC "")
	set(OpenFHE_COMPILE_DEFINITIONS_STATIC
			${OpenFHE_BINFHE_COMPILE_DEFINITIONS_STATIC}
			${OpenFHE_CORE_COMPILE_DEFINITIONS_STATIC}
			${OpenFHE_PKE_COMPILE_DEFINITIONS_STATIC})
endif()
