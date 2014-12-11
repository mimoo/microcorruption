from subprocess import call

#concat i.md -> rapport.md
output = ""
for ii in range(1,15):
	markdown = open(str(ii) + ".md", "r")
	output += markdown.read()
	output += "\n\n"
	markdown.close()

output_file = open("rapport.md", "w")
output_file.write(output)
output_file.close()

# rapport.md -> rapport.tex
call("pandoc -f markdown_github -t latex rapport.md -o rapport.tex")

# layout.tex + rapport.tex -> final.tex
layout = open("layout.tex", "r")
output = layout.read()
layout.close()

content = open("rapport.tex", "r")
output += content.read()
content.close()
output += "\end{document}"

output_file = open("final.tex", "w")
output_file.write(output)
output_file.close()

# final.tex -> 
call("pdflatex -quiet final.tex")