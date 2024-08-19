file(REMOVE_RECURSE
  "../../lib/libOPENFHEbinfhe.pdb"
  "../../lib/libOPENFHEbinfhe.so"
  "../../lib/libOPENFHEbinfhe.so.1"
  "../../lib/libOPENFHEbinfhe.so.1.1.4"
)

# Per-language clean rules from dependency scanning.
foreach(lang CXX)
  include(CMakeFiles/OPENFHEbinfhe.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
