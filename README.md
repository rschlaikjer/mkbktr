# mkbtr

Generate Switch NCA updates using BKTR tables.

## Usage

To use the main mkbktr generation tool:
`$ mkbtr [original nca] [patched nca] [output nca] [/path/to/prod.keys]`

TODO: add guide for small utils

## Building

Building is the standard CMake process:
```
mkdir build
cd build
ccmake ../
make
```

Just use `make` to rebuild with any changes after the makefile is generated. Rerun `ccmake` if you make any changes to the CMakeLists.txt file.