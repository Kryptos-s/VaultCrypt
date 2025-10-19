find_package(Qt5 REQUIRED COMPONENTS Core Widgets)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(GUI_SOURCES
    main.cpp
    MainWindow.h
    MainWindow.cpp
    theme/Theme.hpp
    theme/ThemeManager.hpp
    theme/ThemeManager.cpp
)

add_executable(vaultcrypt-gui WIN32 ${GUI_SOURCES})

target_link_libraries(vaultcrypt-gui PRIVATE 
    vaultcrypt_core
    Qt5::Core
    Qt5::Widgets
)

target_include_directories(vaultcrypt-gui PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
)

install(TARGETS vaultcrypt-gui DESTINATION bin)