/**
 * Cisco Type7 password decoder/encoder
 * Copyright (C) 2012 - Nicolas Biscos (buffer at 0x90 period fr )
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * This should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 **/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

const char xorstring[] = "tfd;kfoA,.iyewrkldJKD";

typedef enum { SUCCESS,
               OUT_OF_MEMORY,
               DIGITAL_FORMAT_ERROR,
               SIZE_NOT_EVEN,
               HEXA_FORMAT_ERROR} ErrorCode;

/**
 * Display help message
 */
void syntax(void)
{
   puts("Syntax: cisco_type7 [-e] <pass>\n"
        "\nRetrieve Cisco Type7 clear text password\n"
        "If -e is defined, encode in type7 format instead\n");
}

/**
 * Return whether a character is a decimal number
 * @param c the character to check
 * @return !=0 is c is a decimal number
 */
int isDecimal(char c)
{
   return ! ( c < '0' || c > '9' );
}

/**
 * Return whether a character is in a-f range
 * @param c the character to check
 * @return !=0 is c is in a-f range
 */
int isHexa1(char c)
{
   return ! ( c < 'a' || c > 'f' );
}

/**
 * Return whether a character is in A-F range
 * @param c the character to check
 * @return !=0 is c is in A-F range
 */
int isHexa2(char c)
{
   return ! ( c < 'A' || c > 'F' );
}

/**
 * Reads one byte and return the value if it is a number character
 * @param[in] c the character to check
 * @param[out] rslt result
 * @param[in] hexBool indicates if should be read as hexadecimal number or decimal number
 * @return !=0 on success
 */
int read1byte(char c, unsigned int *rslt, int hexBool)
{
   if( isDecimal(c) )
      *rslt = c - '0';
   else if( hexBool && isHexa1(c) )
      *rslt = c - 'a'+10;
   else if( hexBool && isHexa2(c) )
      *rslt = c - 'A'+10;
   else
      return EXIT_FAILURE;
   return EXIT_SUCCESS;
}

/**
 * Reads two bytes and return the value if it is a number character
 * @param[in] ptr the string contining the two bytes to read from
 * @param[out] rslt result
 * @param[in] hexBool indicates if should be read as hexadecimal number or decimal number
 * @return !=0 on success
 */
int read2bytes(char *ptr, unsigned int *rslt, int hexBool)
{
   char c1, c2;
   unsigned int i1, i2;

   c1 = *ptr;
   c2 = *(ptr+1);

   if( EXIT_FAILURE == read1byte(c1, &i1, hexBool) )
      return EXIT_FAILURE;
   if( EXIT_FAILURE == read1byte(c2, &i2, hexBool) )
      return EXIT_FAILURE;

   if( hexBool )
      *rslt = i1*16;
   else
      *rslt = i1*10;
   *rslt += i2;
   return EXIT_SUCCESS;
}

/**
 * Encode a string using cisco type7 algorithm
 * @param[in] ptr string to encode
 * @param[out] output the encoded string
 * @return SUCCESS on success, else an error code
 */
ErrorCode encode(char *ptr, char **output)
{
   size_t ilen, olen, xorlen;
   unsigned int i, index;
   char code, c[3];
   xorlen = strlen(xorstring);

   // allocate ilen*2+2 for output. Indeed, each caracter will be encoded in a
   // two digits number, and a 2 bytes prefix is added.
   ilen = strlen(ptr);
   olen = ilen*2 +2;
   *output = (char*)malloc((olen+1)*sizeof(char));
   if( NULL == *output )
   {
      return OUT_OF_MEMORY;
   }
   memset(*output, 0, olen+1);
   
   // Generate random initial index in xorstring
   srand( time(NULL) );
   index = rand() % xorlen;
   sprintf(*output, "%0.2d", index);
   index --;

   // Iterate over characters to build the encoded version of the password
   for( i = 0 ; i < ilen ; ++ptr, ++i )
   {
      code = ((*ptr)^xorstring[index])&0xff;
      snprintf(c, 3, "%0.2X", code);
      strncat(*output, c, olen);
      index = index + 1 % xorlen;
   }
   return SUCCESS;
}

/**
 * Decode cisco type7 password
 * @param[in] ptr string to decode
 * @param[out] output cleartext password
 * @return SUCCESS on success, else an error code
 */
ErrorCode decode(char *ptr, char **output)
{
   size_t ilen, olen, xorlen;
   unsigned int code, i, index;
   char c;
   xorlen = strlen(xorstring);

   // Check that len is even
   ilen = strlen(ptr);
   if( 0 != ilen % 2 )
   {
      return SIZE_NOT_EVEN;
   }

   // output will contain (ilen-2)/2 characters. Indeed, the first 2 bytes indicates the initial 
   // offset in xorstring
   olen = (ilen - 2)/2;
   *output = (char*)malloc((olen+1)*sizeof(char));
   memset(*output, 0, olen+1);

   //Initial offset is decimal only. It starts @ 1, so has to be realigned to match C array
   if( EXIT_FAILURE == read2bytes(ptr, &index, 0) )
   {
      free(*output);
      return DIGITAL_FORMAT_ERROR;
   }
   index--;

   // Iterate over hex numbers and recover clear text password
   for( i = 0 , ptr+=2 ; 
        i < olen ; 
        ++i, ptr+=2)
   {
      if( EXIT_FAILURE == read2bytes(ptr, &code, 1) )
      {
         free(*output);
         return HEXA_FORMAT_ERROR;
      }
      c = xorstring[index]^code;
      *(*output+i) = c;
      index = index+1 % xorlen;
   }
   return SUCCESS;
}

/**
 * Return whether a character is a decimal number
 * @param c the character to check
 * @return !=0 is c is a decimal number
 */
int main(int argc, char **argv)
{
   char *buffer, *ptr;
   int opt;
   ErrorCode (*f)(char *, char**);
   unsigned char doencode = 0;

   if( 0 == argc )
   {
      syntax();
      return EXIT_FAILURE;
   }

   while( -1 != (opt = getopt(argc, argv, "eh") ) )
   {
      switch(opt)
      {
         case 'e':
            doencode = 1;
            break;
         case 'h':
            syntax();
            return EXIT_SUCCESS;
         case '?':
            puts("Syntax error");
            return EXIT_FAILURE;
      }
   }

   if( doencode )
   {
      if( 3 != argc )
      {
         syntax();
         return EXIT_FAILURE;
      }
      f = encode;
      ptr = argv[2];
   }
   else if( 2 != argc )
   {
      syntax();
      return EXIT_FAILURE;
   }
   else
   {
      ptr = argv[1];
      f = decode;
   }

   switch( f(ptr, &buffer) )
   {
      case OUT_OF_MEMORY:
         puts("Memory allocation error");
         return EXIT_FAILURE;
         break;
      case SIZE_NOT_EVEN: 
         puts("Invalid parameter: size must be even");
         return EXIT_FAILURE;
         break;
      case DIGITAL_FORMAT_ERROR:
         puts("Invalid : first 2bytes must be digital");
         return EXIT_FAILURE;
         break;
       case HEXA_FORMAT_ERROR:
         puts("Invalid : must be hex format [0-9a-fA-F]");
         return EXIT_FAILURE;
         break;
      case SUCCESS:
         puts(buffer);
         free(buffer);
         break;
   }
   return EXIT_SUCCESS;
}

