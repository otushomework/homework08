cmake_minimum_required(VERSION 3.2)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

#проект
project(bayan VERSION 0.0.$ENV{TRAVIS_BUILD_NUMBER})

#поиск пакетов-зависимостей
find_package(Boost COMPONENTS system filesystem program_options regex REQUIRED)
#find_package(OpenSSL REQUIRED) #set envvar OPENSSL_ROOT_DIR=/usr/local/Cellar/openssl/1.0.2p/

#сборка исполняемого файла
add_executable(${PROJECT_NAME} main.cpp)

#задаем параметры компилятора
set_target_properties(${PROJECT_NAME} PROPERTIES
  CXX_STANDARD 14
  CXX_STANDARD_REQUIRED ON
  COMPILE_OPTIONS "-Wpedantic;-Wall;-Wextra"
)

#message(WARNING ${OPENSSL_INCLUDE_DIR})

#задаем параметры линковки
set_target_properties(${PROJECT_NAME} PROPERTIES
  #COMPILE_DEFINITIONS BOOST_TEST_DYN_LINK
  INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIR}
)

#set_target_properties(${PROJECT_NAME} PROPERTIES
#  INCLUDE_DIRECTORIES ${OPENSSL_INCLUDE_DIR}
#)

#линкуем библиотеки
target_link_libraries(${PROJECT_NAME}
  ${Boost_LIBRARIES}
#  ${OPENSSL_LIBRARIES}
)

#куда закидывать cli после установки готового пакета
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

#задаем версию в пакете
set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")

set(CPACK_PACKAGE_CONTACT v31337@gmail.com)

#выбираем генератор пакета
set(CPACK_GENERATOR DEB)

set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

include (CPack)

enable_testing()

add_test(test_version_valid test_version)
