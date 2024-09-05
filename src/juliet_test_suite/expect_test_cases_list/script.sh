#!/bin/bash
dirs=()
dir="Juliet/src/testcases"
command=$(ls "$dir")

for d in $command; do
    dir_sub="${dir}/$d"
    javac -cp Juliet/src/testcasesupport/commons-codec-1.5.jar:Juliet/src/testcasesupport/commons-lang-2.5.jar:Juliet/src/testcasesupport/javamail-1.4.4.jar:Juliet/src/testcasesupport/servlet-api.jar Juliet/src/testcasesupport/*.java "$dir_sub"/*.java
done



