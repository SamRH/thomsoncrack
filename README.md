thomsoncrack is a tool designed to generate the default password 
for some Thomson routers based off of information found in the
default SSID.

Dependencies
------------
This product includes software developed by the OpenSSL Project 
for use in the OpenSSL Toolkit. (http://www.openssl.org/)

thomsoncrack depends on the following: the crypto library from OpenSSL and
the POSIX threads API

Usage
-----
The program requires the six letter identifier at the end of the
default SSID to be passed as an argument. Here is an example of
how to use thomsoncrack if you were trying to find potential passwords
for a device with the SSID 'ThomsonCDEA15':

	$ thomsoncrack CDEA15

The output from thomsoncrack would be similar to the following:

	Device Serial Number: CP0911524243
	Key: 68510B64B3
	
	1 potential key(s) found!

The 'Device Serial Number' is a possible serial number for the device
and the 'Key' is the WEP or WPA password for the device if it has not
been changed and the 'Device Serial Number' matches. It is possible for
more than 1 potential key to be found.

How it Works
------------
The last six digits of the default Thomson router SSIDs are a hexedecimal
representation of the last three bytes of a SHA1 sum generated from the
device's serial number. Each serial number consists of the string "CP",
a number representing the year it the device was manufactured, the week
the device was manufacture, and the hexidecimal representation of three
potentially random alpha-numeric characters.

Default passwords for Thomson routers made during the years 2008, 2009, and
2010 are the first 10 characters of a SHA1 string generated from the device
serial numbers. thomsoncrack generates serials, creates a SHA1 sum of generated
serials and then compares the last three bytes with the last three bytes provided
by the default SSID. This narrows down potential keys to only a few.

Credit
------
Stavros Korokithakis - http://www.korokithakis.net/ - His python script for generating
default keys for certain Thomson devices is what I have based this program on.
