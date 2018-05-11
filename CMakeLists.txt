cmake_minimum_required(VERSION 3.9)
project(plugin CXX ASM)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++ -std=c++11 -nodefaultlibs")
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

SET(ASM_OPTIONS "-x assembler-with-cpp")
SET(CMAKE_ASM_FLAGS "${CFLAGS} ${ASM_OPTIONS}" )

set(HEADERS
		include/core.h
		include/plugin.h

		include/process/module.h
		include/process/pattern.h
		include/process/process.h
		include/process/file.h
		include/process/memory.h

		include/hook/hook.h

		include/wrapper/general.h
		include/wrapper/License.h
		include/wrapper/ParameterParser.h

		include/base64.h
)

set(SOURCE
		src/core.cpp
#		src/process/process.cpp
		src/process/file.cpp
		src/process/pattern.cpp
		src/process/memory.cpp
		src/hook/linux_x64.cpp
		src/hook/jmp.S

		src/wrapper/general.cpp
		src/wrapper/PacketParser.cpp
		src/wrapper/License.cpp

		src/base64.cpp
)

include_directories(/usr/local/include/libcxx)

find_package(Boost COMPONENTS system filesystem REQUIRED)

include_directories(teamspeak)
add_library(plugin SHARED ${HEADERS} ${SOURCE})
#target_link_libraries(plugin libstdc++fs.a)
target_link_libraries(plugin c++ c++abi m c gcc_s gcc )
#target_link_libraries(plugin
#		${Boost_FILESYSTEM_LIBRARY}
#		${Boost_SYSTEM_LIBRARY}
#)

add_executable(MemoryTest test/MemoryTest.cpp test/jmp.S)
target_link_libraries(MemoryTest plugin)

#Its important to use the libc library (TeamSpeak uses that as well!