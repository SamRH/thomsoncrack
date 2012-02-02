// vim: noexpandtab sw=4

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "utility.h"

//Convert a sha1 hash to a hexidecimal string
void sha1_to_str(unsigned char *sha1, char *str)
{
	// A sha1 digest is made up of 20 bytes
	for (int i = 0; i < 20; i++)
	{
		sprintf(&str[i*2], "%02hhX", sha1[i]);
	}
	// Ensure the array is NULL-terminated
	str[40] = '\0';
}

//transform all characters of a string into uppercase characters
void str_to_upper(char *str)
{
	for (int i = 0; i < strlen(str); i++)
	{
		str[i] = toupper(str[i]);
	}
}

