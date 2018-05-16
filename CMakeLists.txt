cmake_minimum_required(VERSION 3.9)
project(plugin CXX ASM)

ENABLE_LANGUAGE(ASM_MASM)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

set(SHARED_HEADERS
		include/core.h
		include/plugin.h
        include/config.h

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
        include/ini_reader.h

        include/update/updater.h

        include/gui/helper.h
        include/gui/PluginConfig.h
)

set(SHARED_SOURCE
		src/core.cpp
        src/base64.cpp
        src/config.cpp

#		src/process/process.cpp
		src/process/file.cpp
		src/process/pattern.cpp
		src/process/memory.cpp
        src/process/module.cpp

        src/hook/Hook.cpp

		src/wrapper/general.cpp
		src/wrapper/PacketParser.cpp
		src/wrapper/License.cpp

        src/version/updater.cpp

        src/gui/PluginConfig.cpp
)
#include_directories(teamspeak)

#Qt wrap stuff
set(QT_FILES_UI ui/pluginconfig.ui)
set(QT_HEADER_FILES include/gui/PluginConfig.h)

#Qt stuff
set(AUTOGEN_BUILD_DIR generated/)
find_package(Qt5Widgets REQUIRED)
include_directories(${Qt5Widgets_INCLUDE_DIRS})
add_definitions(${Qt5Widgets_DEFINITIONS})
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${Qt5Widgets_EXECUTABLE_COMPILE_FLAGS}")


qt5_wrap_ui(QT_COMPILED_UI "${QT_FILES_UI}")
qt5_wrap_cpp(QT_COMPILED_SOURCE "${QT_HEADER_FILES}")

if(MSVC)
    set(CMAKE_ASM_COMPILER "$ENV{VCInstallDir}Tools/MSVC/14.12.25827/bin/Hostx64/x64/ml64.exe") #/errorReport:none
    set(CMAKE_ASM_COMPILE_OBJECT "<CMAKE_ASM_COMPILER> <DEFINES> <INCLUDES> <FLAGS> /Fo <OBJECT> <SOURCE> /c /W2 /nologo")

    #We do a windows build!
    set(CMAKE_CXX_FLAGS_RELEASE "/MT") #We dont want optimasations etc!
    set(WINDOWS_SHARED_SOURCE
            include/hook/HookWindows.h
            src/hook/win/Hook.cpp
            src/hook/win/jmp.S
    )

    #curl
    #I donst know how to install a library "right" within windows so im using absolute paths instead :D
    include_directories(C:/msvc_libs/curl/include)
    add_definitions(-DCURL_STATICLIB)
    set(CURL_LIBRARIES "C:/msvc_libs/curl/msbuild/lib/Release/libcurl.lib")

    add_library(plugin SHARED ${SHARED_HEADERS} ${SHARED_SOURCE} ${WINDOWS_SHARED_SOURCE} ${QT_COMPILED_UI} ${QT_COMPILED_SOURCE})
    target_link_libraries(plugin ${CURL_LIBRARIES} Qt5::Widgets Qt5::Core  Qt5::Gui ws2_32 Wldap32)
    add_custom_command(TARGET plugin POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin> ${CMAKE_SOURCE_DIR}/package/plugins/tspatch_win64.dll
    )

    add_executable(MemoryTest test/win/Main.cpp ${SHARED_HEADERS} ${SHARED_SOURCE} ${WINDOWS_SHARED_SOURCE} ${QT_COMPILED_UI} ${QT_COMPILED_SOURCE})
    target_link_libraries(MemoryTest ${CURL_LIBRARIES} Qt5::Widgets ws2_32 Wldap32)
else()
    #Its important to use the libc library (TeamSpeak uses that as well!
    #We run stuff for linux :D
    SET(CMAKE_ASM_FLAGS "${CFLAGS} -x assembler-with-cpp")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc++ -std=c++11 -nodefaultlibs")

    set(LINUX_SHARED_SOURCE
            src/hook/linux/linux_x64.cpp
            src/hook/linux/jmp.S
    )

    include_directories(/usr/local/include/libcxx)

    add_library(plugin SHARED ${SHARED_HEADERS} ${SHARED_SOURCE} ${LINUX_SHARED_SOURCE})
    target_link_libraries(plugin curl c++abi m gcc_s gcc c++ c m stdc++)
    add_custom_command(TARGET plugin COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin> ${CMAKE_SOURCE_DIR}/package/plugins/tspatch_linux_64.so)

    add_executable(MemoryTest test/linux/MemoryTest.cpp test/linux/jmp.S)
    target_link_libraries(MemoryTest plugin)
endif()