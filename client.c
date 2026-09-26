#include <stdio.h>
#include <string.h>

int main() {
    char filename[256];

    printf("Enter the file name to read: ");
    fgets(filename, sizeof(filename), stdin);
    filename[strcspn(filename, "\n")] = '\0';

    printf("You entered: %s\n", filename);
    return 0;
}
