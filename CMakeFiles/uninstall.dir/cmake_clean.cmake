file(REMOVE_RECURSE
  "CMakeCache.txt"
  "demoData"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/uninstall.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
