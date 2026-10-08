add_library(libSceGameLiveStreaming SHARED EXCLUDE_FROM_ALL Export.cpp)
target_include_directories(libSceGameLiveStreaming PRIVATE ${LIBS_INCLUDE_DIR})
configure_windows_unwind(libSceGameLiveStreaming)

if(BUILD_TESTING)
    add_test_executable(guest_game_live_streaming_tests ${LIBS_INCLUDE_DIR}/tests/GuestGameLiveStreaming.cpp)
    target_include_directories(guest_game_live_streaming_tests PRIVATE ${LIBS_INCLUDE_DIR})
    target_link_libraries(guest_game_live_streaming_tests PRIVATE libSceGameLiveStreaming)
    add_test(NAME guest_game_live_streaming COMMAND guest_game_live_streaming_tests)
    if(WIN32)
        set_tests_properties(guest_game_live_streaming PROPERTIES ENVIRONMENT_MODIFICATION
            "PATH=path_list_prepend:$<TARGET_FILE_DIR:libSceGameLiveStreaming>")
    endif()
endif()
