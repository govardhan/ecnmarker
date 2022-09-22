cmake_minimum_required(VERSION 3.22)

project(ecnmarker C)

set(CMAKE_C_COMPILER clang)
set(CMAKE_C_FLAGS "-O2 -S -emit-llvm -g -target bpf -mtune=v3")
set(CMAKE_C_LINK_EXECUTABLE "llc -filetype=obj -o <TARGET> <OBJECTS>")

include(TestBigEndian)
test_big_endian(is_big_endian)
if(is_big_endian)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mbig-endian")
	set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_LINK_EXECUTABLE} -march=bpfeb")
else()
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mlittle-endian")
	set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_LINK_EXECUTABLE} -march=bpfel")
endif()

# generate C header file with all kernel types from kernel BTF information
# this requires a kernel with CONFIG_DEBUG_INFO_BTF enabled
execute_process(COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c OUTPUT_FILE vmlinux.h)

add_compile_definitions(BPF_CORE)
add_executable(ecnmarker-bpf.o ecnmarker-bpf.c)
install(TARGETS ecnmarker-bpf.o RUNTIME DESTINATION /lib/ecnmarker)
