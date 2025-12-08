message(STATUS "======================================")
message(STATUS "Fetching packages")
message(STATUS "======================================")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

# add packages here
