file(REMOVE_RECURSE
  "CMakeCache.txt"
  "demoData"
  "CMakeFiles/allexamples"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/allexamples.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
