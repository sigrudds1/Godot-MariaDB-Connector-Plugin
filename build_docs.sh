#!/bin/bash

cd ~/dev/repos/godot_addons/mariadb_connector/
scons
cd ~/dev/repos/godot_addons/mariadb_connector/demo
~/dev/GodotEngine-Builds/Godot_v4.4.1-stable_linux.x86_64 --doctool ../ --gdextension-docs
cd ~/dev/repos/godot_addons/mariadb_connector/
scons