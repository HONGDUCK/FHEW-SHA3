file(REMOVE_RECURSE
  "../../lib/libOPENFHEpke.pdb"
  "../../lib/libOPENFHEpke.so"
  "../../lib/libOPENFHEpke.so.1"
  "../../lib/libOPENFHEpke.so.1.1.4"
)

# Per-language clean rules from dependency scanning.
foreach(lang CXX)
  include(CMakeFiles/OPENFHEpke.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
