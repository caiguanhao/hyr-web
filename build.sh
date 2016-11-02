#!/bin/bash

mkdir -p vendor/precompiled

find * -name '*.html' -o -name '*.js' | awk '
  BEGIN {
    print "package precompiled"
  }
  {
    file=$0;
    gsub(/[^A-Za-z0-9]/, "_", file);
    print "";
    printf "const File_%s = `", file;
    while((getline line < $0) > 0) {
      print line
    };
    print "`"
  }
' > vendor/precompiled/files.go

go build
