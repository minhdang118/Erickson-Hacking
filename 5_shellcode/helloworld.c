#include <stdio.h>
#include <unistd.h>

int main()
{
    char str[1024] = "How are you doing?\n";
    printf("Hello, world!\n");
    // write(0, str, sizeof(str));
    write(1, str, sizeof(str));
    // write(2, str, sizeof(str));
    return 0;
}
