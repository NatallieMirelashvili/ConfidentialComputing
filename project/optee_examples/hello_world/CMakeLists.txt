project (optee_example_hello_world C)

set (SRC host/main.c
		ta/hello_world_ta.c)

add_executable (${PROJECT_NAME} ${SRC})

target_include_directories(${PROJECT_NAME}
			   PRIVATE ta/include
			   PRIVATE include)

target_link_libraries (${PROJECT_NAME} PRIVATE teec)

if(DEFINED ENV{OPTEE_WORKSPACE})
	include_directories($ENV{OPTEE_WORKSPACE}/optee_client/libteec/include)
endif()

install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
