output = ""
for ii in range(1,15):
	markdown = open(str(ii) + ".md", "r")
	output += markdown.read()
	output += "\n\n"
	markdown.close()

output_file = open("rapport.md", "w")
output_file.write(output)
output_file.close()