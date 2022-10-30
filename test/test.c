#include <string.h>
#include <stdio.h>

int main() {
    char* chuj = "libero reprehenderit esse! Consectetur architecto ut";
    memcpy(chuj+2, "SOSI BIBU", 10);
    printf("%s\n", chuj);

}