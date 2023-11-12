#! /bin/bash
mkdir -p debug
gcc -g -Wall -Wextra src/main.c -o debug/socks
