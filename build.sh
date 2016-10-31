#!/bin/bash

find * -name '*.html' -o -name '*.js' | awk '
  BEGIN {
    print "package main"
  }
  {
    file=$0;
    gsub(/[^A-Za-z0-9]/, "_", file);
    print "";
    printf "const %s = `", file;
    while((getline line < $0) > 0) {
      print line
    };
    print "`"
  }
' > html.go

go build
