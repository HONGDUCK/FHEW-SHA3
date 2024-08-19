file(REMOVE_RECURSE
  "CMakeCache.txt"
  "demoData"
  "CMakeFiles/tcm_clean"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/tcm_clean.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
