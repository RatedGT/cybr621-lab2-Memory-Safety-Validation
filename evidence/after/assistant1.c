#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    FILE *file;
    time_t now;
    char timestamp[26];
    
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <log_message>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    int fd = open("userlog.txt", O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        perror("Error opening userlog.txt");
        return EXIT_FAILURE;
    }
    file = fdopen(fd, "a");
    if (file == NULL) {
        perror("Error opening userlog.txt stream");
        close(fd);
        return EXIT_FAILURE;
    }
    
    time(&now);
    ctime_r(&now, timestamp);
    timestamp[strcspn(timestamp, "\n")] = '\0';
    
    if (fprintf(file, "[%s] %s: %s\n", timestamp, argv[1], argv[2]) < 0) {
        perror("Error writing to userlog.txt");
        fclose(file);
        return EXIT_FAILURE;
    }
    
    if (fclose(file) != 0) {
        perror("Error closing userlog.txt");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}