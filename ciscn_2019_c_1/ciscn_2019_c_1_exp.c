#include<stdio.h>
#include<string.h>

unsigned char encrypt(char x){
    if ( x <= 96 || x > 122 )
    {
      if ( x <= 64 || x > 90 )
      {
        if ( x > 47 && x <= 57 )
          x ^= 0xFu;
      }
      else
      {
        x ^= 0xEu;
      }
    }
    else
    {
      x ^= 0xDu;
    }
    return x;
}

int main(){
  int x = 0;
  unsigned char address[4] = { 0xc0, 0x06, 0x40 };
  unsigned char s[4] = { 0 };

  for(int j = 0; j < 4; j++){
    for(unsigned char i = 0; i <= (unsigned char)255; i++){
      if(encrypt(i) == address[j]){
      	printf("%02x", i);
      	s[j] = i;
      	break;
      }
    }  
  }
  printf("\n");
  puts(s);
  return 0;
}
