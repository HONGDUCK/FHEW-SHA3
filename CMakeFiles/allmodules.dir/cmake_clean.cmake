file(REMOVE_RECURSE
  "CMakeCache.txt"
  "demoData"
  "CMakeFiles/allmodules"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/allmodules.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
