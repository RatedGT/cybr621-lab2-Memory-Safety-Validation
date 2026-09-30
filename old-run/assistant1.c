//Github copilot

#include <stdio.h>


int main(int argc, char *argv[]) {

if (argc != 3) {

fprintf(stderr, "Usage: %s  <log_message>\n", argv[0]);

return 1;

}

FILE *file = fopen("userlog.txt", "a");
if (file == NULL) {
    perror("Error opening userlog.txt");
    return 1;
}

if (fprintf(file, "%s: %s\n", argv[1], argv[2]) < 0) {
    perror("Error writing to userlog.txt");
    fclose(file);
    return 1;
}

if (fclose(file) != 0) {
    perror("Error closing userlog.txt");
    return 1;
}

return 0;
}