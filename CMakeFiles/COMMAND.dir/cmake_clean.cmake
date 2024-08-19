file(REMOVE_RECURSE
  "CMakeCache.txt"
  "demoData"
  "CMakeFiles/COMMAND"
)

# Per-language clean rules from dependency scanning.
foreach(lang )
  include(CMakeFiles/COMMAND.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
