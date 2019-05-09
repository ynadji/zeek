#!/bin/bash

PLUGIN_FOLDER=llpoc-analyzers

rm build
rm plugins/${PLUGIN_FOLDER}/build
ln -s cmake-build-$1 build
ln -s cmake-build-$1 plugins/${PLUGIN_FOLDER}/build
ls -la build
ls -la plugins/${PLUGIN_FOLDER}/build
