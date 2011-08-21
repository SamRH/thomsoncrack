#include <string.h>
#include <ctype.h>

#include "lookup_hex.h"
#include "utility.h"

// Convert a sha1 hash to a hexidecimal string
void sha1_to_str(unsigned char *sha1, char *str)
{
	for (int i = 0; i < 20; i++)
	{
		memcpy(str + (i*2), lookup_hex[(int)sha1[i]], 2);
	}
}

//transform all characters of a string into uppercase characters
void str_to_upper(char *str)
{
	for (int i = 0; i < strlen(str); i++)
	{
		str[i] = toupper(str[i]);
	}
}

