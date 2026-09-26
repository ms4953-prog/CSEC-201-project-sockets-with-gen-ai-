#include <stdio.h>

int main() {
    char filename[256];

    printf("Enter the file name to read: ");
    fgets(filename, sizeof(filename), stdin);

    printf("You entered: %s", filename);
    return 0;
}
