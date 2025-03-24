#!/bin/bash

#scons platform=linux arch=arm64 target=template_debug
#scons platform=linux arch=arm64 target=template_release
scons platform=linux arch=x86_64 target=template_debug
scons platform=linux arch=x86_64 target=template_release
scons platform=windows target=template_debug
scons platform=windows target=template_release
