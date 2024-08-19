file(REMOVE_RECURSE
  "CMakeCache.txt"
  "demoData"
  "CMakeFiles/tcm"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/tcm.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
