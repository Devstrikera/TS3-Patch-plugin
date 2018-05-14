cmake_minimum_required(VERSION 3.9)
project(plugin CXX ASM)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(SHARED_HEADERS
		include/core.h
		include/plugin.h

		include/process/module.h
		include/process/pattern.h
#		include/process/process.h
		include/process/file.h
		include/process/memory.h

        include/hook/Hook.h

		include/wrapper/general.h
		include/wrapper/License.h
		include/wrapper/ParameterParser.h

		include/base64.h
)

set(SHARED_SOURCE
		src/core.cpp
#		src/process/process.cpp
		src/process/file.cpp
		src/process/pattern.cpp
		src/process/memory.cpp
        src/process/module.cpp

        src/hook/Hook.cpp

		src/wrapper/general.cpp
		src/wrapper/PacketParser.cpp
		src/wrapper/License.cpp
		src/base64.cpp
)

include_directories(teamspeak)
#SET(CMAKE_ASM_FLAGS "${CFLAGS} -x assembler-with-cpp")
if(MSVC)
    #We do a windows build!
    ENABLE_LANGUAGE(ASM_MASM)
    set(CMAKE_ASM_COMPILER "$ENV{VCInstallDir}Tools/MSVC/14.12.25827/bin/Hostx64/x64/ml64.exe") #/errorReport:none
    set(CMAKE_ASM_COMPILE_OBJECT "<CMAKE_ASM_COMPILER> <DEFINES> <INCLUDES> <FLAGS> /Fo <OBJECT> <SOURCE> /c /W2 /nologo")

    set(CMAKE_CXX_FLAGS_RELEASE "/MT") #We dont want optimasations etc!
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT") #/MT for static linking of the msvc shit
    set(WINDOWS_SHARED_SOURCE
            include/hook/HookWindows.h
            src/hook/win/Hook.cpp
            src/hook/win/jmp.S
    )

    add_library(plugin SHARED ${SHARED_HEADERS} ${SHARED_SOURCE} ${WINDOWS_SHARED_SOURCE})
    target_link_libraries(plugin ws2_32)
    add_custom_command(TARGET plugin POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin> ${CMAKE_SOURCE_DIR}/package/plugins/tspatch_win64.dll
    )

    add_executable(MemoryTest test/win/Main.cpp)
    target_link_libraries(MemoryTest plugin)
    add_custom_command(TARGET MemoryTest
            PRE_BUILD
            COMMAND "" /c /W2 /nologo /errorReport:none
            /Fo${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/MemoryTest.dir/xxx.rsp
            "${CMAKE_SOURCE_DIR}/src/hook/win/jmp.S"
            COMMENT "Building asm file")
    #target_sources(MemoryTest PUBLIC "xxx.rsp")
else()
    #Its important to use the libc library (TeamSpeak uses that as well!
    #We run stuff for linux :D
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++ -std=c++11 -nodefaultlibs")

        set(LINUX_SHARED_SOURCE
                src/hook/linux/linux_x64.cpp
                src/hook/linux/jmp.S
        )

    include_directories(/usr/local/include/libcxx)

    add_library(plugin SHARED ${HEADERS} ${SOURCE} ${LINUX_SHARED_SOURCE})
    target_link_libraries(plugin c++ c++abi m c gcc_s gcc )

    add_executable(MemoryTest test/linux/MemoryTest.cpp test/linux/jmp.S)
    target_link_libraries(MemoryTest plugin)
endif()