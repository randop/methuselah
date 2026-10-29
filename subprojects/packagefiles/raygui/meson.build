project('raygui', 'c')

raygui_inc = include_directories('src', is_system: true)
raygui_dep = declare_dependency(include_directories: raygui_inc)
meson.override_dependency('raygui', raygui_dep)
