# aps5-fex runs the relinker's Linux output on arm64 macOS through FEXCore, built by build-fexcore.sh.
enable_language(ASM)
set(APS5_FEXCORE_BUILD_DIR "${APS5_FEXCORE_DIR}/build-macos" CACHE PATH "The FEXCore build directory")

add_executable(aps5-fex src/Main.cpp src/Bridge.cpp src/GuestCpu.cpp src/GuestImage.cpp src/GuestProgram.cpp src/Trampolines.S)
target_compile_features(aps5-fex PRIVATE cxx_std_20)
target_include_directories(aps5-fex PRIVATE
    ${APS5_FEXCORE_DIR}/FEXCore/include
    ${APS5_FEXCORE_BUILD_DIR}/include
    ${APS5_FEXCORE_DIR}/FEXHeaderUtils
    ${APS5_FEXCORE_DIR}/External/fmt/include
    ${APS5_FEXCORE_DIR}/External/range-v3/include
    ${APS5_FEXCORE_DIR}/External/unordered_dense/include)
target_link_libraries(aps5-fex PRIVATE
    ${APS5_FEXCORE_BUILD_DIR}/FEXCore/Source/libFEXCore.a
    ${APS5_FEXCORE_BUILD_DIR}/FEXCore/Source/libFEXCore_Base.a
    ${APS5_FEXCORE_BUILD_DIR}/FEXCore/Source/libJemallocLibs.a
    ${APS5_FEXCORE_BUILD_DIR}/External/fmt/libfmt.a
    ${APS5_FEXCORE_BUILD_DIR}/External/xxhash/cmake_unofficial/libxxhash.a
    ${APS5_FEXCORE_BUILD_DIR}/External/cephes/libcephes_128bit.a
    ${APS5_FEXCORE_BUILD_DIR}/External/SoftFloat-3e/libsoftfloat_3e.a)

if(BUILD_TESTING)
    find_package(Python3 QUIET COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        # Runs the relinked programs, so it needs the patched libraries: build the libs target first.
        add_test(NAME fex_fixtures COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_fex_fixtures.py
            $<TARGET_FILE:relinker> $<TARGET_FILE:aps5-fex> ${CMAKE_BINARY_DIR}/core/libs/libs)
    endif()
endif()
