file(REMOVE_RECURSE
  "CMakeCache.txt"
  "demoData"
  "CMakeFiles/testall"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/testall.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
