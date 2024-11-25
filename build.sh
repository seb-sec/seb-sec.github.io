#!/bin/sh

PREFIX=src
OUTPUT=docs

run_pandoc () {
    pandoc --toc --toc-depth 3 -s --css /assets/css/dark.css -i $1 -o $2 --template=template.html --mathjax=https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js
}

for file in $(find $PREFIX -name "*.md"); do
    echo $file
    # Get name without extension
    extless="${file%.*}"
    run_pandoc $file "$extless.html"
done

# Copy all site parts to the output
rm -rf $OUTPUT
cp $PREFIX $OUTPUT -r
find $OUTPUT -name "*.md" -type f -delete
find $PREFIX -name "*.html" -type f -delete
