/*
 *	Global Variable Extractor
 *	from dynamically linked ELF executable file
 *
 *	Jun 7, 2012
 *	written by Kim, Wooil
 *	kim844@illinois.edu
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE	*fp, *fp2;
char	line[200];
unsigned long int	addr;
char	c1, c2;
char	section[20];
unsigned int		size;
char	name[100];
int		line_num;


int main(int argc, char *argv[])
{
	if (argc < 3) {
		printf("[Usage] globalvariable {input file} {output file}\n\n\n");
		return -1;
	}

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		printf("Failed to open file %s\n", argv[1]);
		return -1;
	}

	fp2 = fopen(argv[2], "w");
	if (fp2 == NULL) {
		printf("Failed to open file %s\n", argv[2]);
		return -1;
	}

	line_num = -1;
	while ( fgets(line, 200, fp) )
	{
		line_num++;
		sscanf(line, "%lx %c %c", &addr, &c1, &c2);
		//if (c1 != 'g')
		//	continue;
		if (c2 == '.')
			continue;

		// now global variable
		sscanf(line, "%lx %c %c %s %x %s", &addr, &c1, &c2, &section, &size, &name[0]);
		if (strcmp(section, ".rodata") && strcmp(section, ".data") && strcmp(section, ".bss")) {
			printf("line %d in %s does not have valid section name.\n", line_num, argv[1]);
			printf("[%s]\n", line);
			//return -1;
			continue;
		}

		// size is zero, skip it.
		if (size == 0)
			continue;

		// Skip _IO_stdin_used
		if (!strcmp(name, "_IO_stdin_used"))
			continue;

		// Skip Pthread data 
		if (!strcmp(name, "PThreadTable"))
			continue;

		// Skip GLIBC related data
		if (strstr(name, "@@GLIBC"))
			continue;

		fprintf(fp2, "%s %lx %x\n", name, addr, size);		
	}

	fclose(fp);
	fclose(fp2);

	return 0;
}
