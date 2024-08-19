file(REMOVE_RECURSE
  "CMakeCache.txt"
  "demoData"
  "CMakeFiles/third-party"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/third-party.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
