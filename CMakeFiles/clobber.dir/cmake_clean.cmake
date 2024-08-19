file(REMOVE_RECURSE
  "CMakeCache.txt"
  "demoData"
  "CMakeFiles/clobber"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/clobber.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
