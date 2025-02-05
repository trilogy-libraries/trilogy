################################
# GLOBAL CONFIGURATION VARIABLES
################################

cmake_minimum_required(VERSION 3.10)
project(trilogy LANGUAGES C VERSION 2.9.0)

option(BUILD_EXECUTABLE  "Build trilogy executable"     ON)
option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

######################################
# SET PACKAGE AND DEPLOYMENT VARIABLES
######################################
file(GLOB SOURCE_FILES ${PROJECT_SOURCE_DIR}/src/**/*.c ${PROJECT_SOURCE_DIR}/src/*.c)
file(GLOB CORE_HEADERS ${PROJECT_SOURCE_DIR}/inc/**/*.h ${PROJECT_SOURCE_DIR}/inc/*.h)

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${CMAKE_PROJECT_VERSION})
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION 2)

include_directories(${PROJECT_SOURCE_DIR}/inc)
# Generate position independent code
set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(BUILD_EXECUTABLE)
   add_executable(trilogy_exec example/trilogy_query.c)

   target_link_libraries(trilogy_exec ${PROJECT_NAME})

   set_target_properties(trilogy_exec PROPERTIES OUTPUT_NAME trilogy_query POSITION_INDEPENDENT_CODE ON)
endif()

###################
# FIND REQUIREMENTS
###################

find_package(OpenSSL REQUIRED)
if (OPENSSL_FOUND)
   target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto OpenSSL::SSL)
   include_directories(${OPENSSL_INCLUDE_DIR})
endif()

#################
# CONFIGURE FILES
#################

if(NOT WIN32)
   include(GNUInstallDirs)
endif()
include(CMakePackageConfigHelpers)

file(WRITE ${PROJECT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
   "include(\${CMAKE_CURRENT_LIST_DIR}/${PROJECT_NAME}-targets.cmake)
   set(${PROJECT_NAME}_INCLUDE_DIRS ${CMAKE_INSTALL_PREFIX}/include/${PROJECT_NAME})
   set(${PROJECT_NAME}_LINK_DIRS ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
   set(${PROJECT_NAME}_LIBRARIES ${PROJECT_NAME} ${AIO_LIBRARIES})
   set(${PROJECT_NAME}_FOUND TRUE)")

write_basic_package_version_file(
   "${PROJECT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake"
   VERSION ${PROJECT_VERSION}
   COMPATIBILITY SameMajorVersion)

################################
# EXPORT AND INSTALL INFORMATION
################################

install(FILES
   "${PROJECT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
   "${PROJECT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake"
   DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
   COMPONENT Development)

install(FILES ${CORE_HEADERS}
   DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
   COMPONENT headers)

install(TARGETS ${PROJECT_NAME}
   EXPORT ${PROJECT_NAME}-targets
   ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Development
   LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Runtime)

install(EXPORT ${PROJECT_NAME}-targets
   NAMESPACE ${PROJECT_NAME}::
   FILE ${PROJECT_NAME}-targets.cmake
   DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

if(BUILD_EXECUTABLE)
   install(TARGETS trilogy_exec
      RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime)
endif()
