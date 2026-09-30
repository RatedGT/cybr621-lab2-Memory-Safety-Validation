//Claude Code

/*
 * userlog.c - Securely append a username and a log message to "userlog.txt".
 *
 * Usage:
 *     ./userlog <username> <message>
 *
 * Suggested build (hardened):
 *     gcc -std=c11 -Wall -Wextra -Wpedantic -Wformat=2 -Wconversion -O2 \
 *         -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie \
 *         -Wl,-z,relro,-z,now -o userlog userlog.c
 *
 * Security properties:
 *   - The number of arguments, their lengths and their character sets are all checked.
 *   - Only printable ASCII is accepted, so the log cannot be forged with
 *     injected newlines or terminal escape sequences.
 *   - All strings are built with bounded functions (snprintf, strnlen), and
 *     every result is checked for truncation.
 *   - Unsafe functions (gets, strcpy, strcat, sprintf, scanf...) are not used.
 *   - The file is opened with O_NOFOLLOW to reject symlinks. It is created with
 *     mode 0600 and must be a regular file with one link that the caller owns.
 *   - A POSIX write lock stops lines from concurrent runs from interleaving.
 *   - Every system call's return value is checked, including write, fsync and close.
 */

#define _XOPEN_SOURCE 700   /* POSIX.1-2008 + XSI: O_NOFOLLOW, O_CLOEXEC, strnlen, gmtime_r, fsync */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ---- Configuration limits ---------------------------------------------- */

#define LOG_FILENAME     "userlog.txt"
#define USERNAME_MAX     32U     /* Max username length (bytes, excl. NUL)   */
#define MESSAGE_MAX      1024U   /* Max message length (bytes, excl. NUL)    */
#define TIMESTAMP_SIZE   32U     /* Buffer for ISO-8601 UTC timestamp        */

/* Fixed text in each line: " user=" + " msg=" + "\n" plus some slack. */
#define LINE_OVERHEAD    32U
#define LINE_BUF_SIZE    (TIMESTAMP_SIZE + USERNAME_MAX + MESSAGE_MAX + LINE_OVERHEAD)

/* ---- Input validation --------------------------------------------------- */

/*
 * Returns 1 if 'c' is an ASCII letter. The check uses explicit ranges instead of
 * isalpha() so the result does not depend on the locale.
 */
static int is_ascii_alpha(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* Returns 1 if 'c' is an ASCII decimal digit. */
static int is_ascii_digit(char c)
{
    return c >= '0' && c <= '9';
}

/*
 * Checks the username. It must:
 *   - be 1..USERNAME_MAX bytes long
 *   - start with a letter or underscore (so it cannot look like an option)
 *   - contain only letters, digits, '_', '-', or '.'
 * Returns 1 if valid and 0 otherwise.
 */
static int validate_username(const char *name)
{
    size_t len;
    size_t i;

    if (name == NULL) {
        return 0;
    }

    /* strnlen never reads more than USERNAME_MAX + 1 bytes. */
    len = strnlen(name, USERNAME_MAX + 1U);
    if (len == 0U || len > USERNAME_MAX) {
        return 0;
    }

    if (!is_ascii_alpha(name[0]) && name[0] != '_') {
        return 0;
    }

    for (i = 1U; i < len; i++) {
        char c = name[i];
        if (!is_ascii_alpha(c) && !is_ascii_digit(c) &&
            c != '_' && c != '-' && c != '.') {
            return 0;
        }
    }

    return 1;
}

/*
 * Checks the log message. It must:
 *   - be 1..MESSAGE_MAX bytes long
 *   - contain only printable ASCII (0x20..0x7E). This rejects newlines, carriage
 *     returns, tabs, escape characters and other control bytes that could forge
 *     log entries or change what a terminal displays.
 *   - not be made up only of spaces
 * Returns 1 if valid and 0 otherwise.
 */
static int validate_message(const char *msg)
{
    size_t len;
    size_t i;
    int has_non_space = 0;

    if (msg == NULL) {
        return 0;
    }

    len = strnlen(msg, MESSAGE_MAX + 1U);
    if (len == 0U || len > MESSAGE_MAX) {
        return 0;
    }

    for (i = 0U; i < len; i++) {
        unsigned char c = (unsigned char)msg[i];
        if (c < 0x20U || c > 0x7EU) {
            return 0;
        }
        if (c != ' ') {
            has_non_space = 1;
        }
    }

    return has_non_space;
}

/* ---- Helpers ------------------------------------------------------------ */

/*
 * Writes the current UTC time to 'buf' in the form "YYYY-MM-DDTHH:MM:SSZ".
 * Returns 0 on success and -1 on failure.
 */
static int make_timestamp(char *buf, size_t bufsize)
{
    time_t now;
    struct tm tm_utc;

    if (buf == NULL || bufsize == 0U) {
        return -1;
    }

    now = time(NULL);
    if (now == (time_t)-1) {
        return -1;
    }

    /* gmtime_r is the reentrant version and does not use static storage. */
    if (gmtime_r(&now, &tm_utc) == NULL) {
        return -1;
    }

    /* strftime returns 0 if the result does not fit in the buffer. */
    if (strftime(buf, bufsize, "%Y-%m-%dT%H:%M:%SZ", &tm_utc) == 0U) {
        return -1;
    }

    return 0;
}

/*
 * Writes exactly 'len' bytes from 'buf' to 'fd'. It retries after partial
 * writes and after interruption by a signal (EINTR).
 * Returns 0 on success and -1 on failure, with errno set.
 */
static int write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0U;

    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;           /* Interrupted: retry the write. */
            }
            return -1;
        }
        if (n == 0) {
            errno = EIO;            /* Stop instead of looping forever. */
            return -1;
        }
        off += (size_t)n;
    }

    return 0;
}

/*
 * Waits for an exclusive (write) lock on the whole file, retrying after EINTR.
 * Returns 0 on success and -1 on failure.
 */
static int lock_file(int fd)
{
    struct flock fl;

    memset(&fl, 0, sizeof fl);
    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;                /* 0 means "to end of file", i.e. the whole file. */

    while (fcntl(fd, F_SETLKW, &fl) == -1) {
        if (errno != EINTR) {
            return -1;
        }
    }

    return 0;
}

/* Prints how to use the program. argv[0] is not printed because it is not trusted. */
static void print_usage(void)
{
    fprintf(stderr,
            "Usage: userlog <username> <message>\n"
            "  username: 1-%u chars, starts with a letter or '_',\n"
            "            then letters, digits, '_', '-', '.'\n"
            "  message : 1-%u printable ASCII characters\n",
            USERNAME_MAX, MESSAGE_MAX);
}

/* ---- Main --------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    const char *username;
    const char *message;
    char timestamp[TIMESTAMP_SIZE];
    char line[LINE_BUF_SIZE];
    int line_len;
    int fd = -1;
    int status = EXIT_FAILURE;
    struct stat st;

    /* 1. Check the argument count. Exactly two user arguments are required. */
    if (argc != 3 || argv == NULL || argv[1] == NULL || argv[2] == NULL) {
        print_usage();
        return EXIT_FAILURE;
    }

    username = argv[1];
    message  = argv[2];

    /* 2. Validate both inputs before doing anything with them. */
    if (!validate_username(username)) {
        fprintf(stderr, "Error: invalid username.\n");
        print_usage();
        return EXIT_FAILURE;
    }

    if (!validate_message(message)) {
        fprintf(stderr, "Error: invalid message.\n");
        print_usage();
        return EXIT_FAILURE;
    }

    /* 3. Build the timestamp. */
    if (make_timestamp(timestamp, sizeof timestamp) != 0) {
        fprintf(stderr, "Error: unable to obtain current time.\n");
        return EXIT_FAILURE;
    }

    /*
     * 4. Build the complete log line in a fixed-size buffer.
     *    snprintf always NUL-terminates. A negative return value, or one that
     *    is sizeof(line) or larger, means an error or truncation.
     */
    line_len = snprintf(line, sizeof line, "%s user=%s msg=%s\n",
                        timestamp, username, message);
    if (line_len < 0 || (size_t)line_len >= sizeof line) {
        fprintf(stderr, "Error: failed to format log entry.\n");
        return EXIT_FAILURE;
    }

    /*
     * 5. Open the log file securely:
     *      O_WRONLY   - write-only access
     *      O_APPEND   - every write goes to the end of the file
     *      O_CREAT    - create the file if it does not exist
     *      O_NOFOLLOW - fail if the final path component is a symlink
     *      O_CLOEXEC  - do not pass the descriptor on to child processes
     *    A new file is created with mode 0600 (owner read/write only).
     */
    fd = open(LOG_FILENAME,
              O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
              S_IRUSR | S_IWUSR);
    if (fd == -1) {
        fprintf(stderr, "Error: cannot open '%s': %s\n",
                LOG_FILENAME, strerror(errno));
        return EXIT_FAILURE;
    }

    /*
     * 6. Check the file we actually opened. fstat on the open descriptor avoids
     *    the race between checking a path and using it (TOCTOU). Reject anything
     *    that is not a regular file, has extra hard links, or belongs to
     *    someone else.
     */
    if (fstat(fd, &st) == -1) {
        fprintf(stderr, "Error: cannot stat '%s': %s\n",
                LOG_FILENAME, strerror(errno));
        goto cleanup;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: '%s' is not a regular file.\n", LOG_FILENAME);
        goto cleanup;
    }

    if (st.st_nlink != 1) {
        fprintf(stderr, "Error: '%s' has unexpected hard links.\n", LOG_FILENAME);
        goto cleanup;
    }

    if (st.st_uid != geteuid()) {
        fprintf(stderr, "Error: '%s' is not owned by the current user.\n",
                LOG_FILENAME);
        goto cleanup;
    }

    /* 7. Lock the file so that entries from concurrent runs never mix. */
    if (lock_file(fd) != 0) {
        fprintf(stderr, "Error: cannot lock '%s': %s\n",
                LOG_FILENAME, strerror(errno));
        goto cleanup;
    }

    /* 8. Write the whole entry, handling partial writes and interruptions. */
    if (write_all(fd, line, (size_t)line_len) != 0) {
        fprintf(stderr, "Error: failed writing to '%s': %s\n",
                LOG_FILENAME, strerror(errno));
        goto cleanup;
    }

    /* 9. Flush the data to disk so the entry is not lost if the system crashes. */
    if (fsync(fd) == -1) {
        fprintf(stderr, "Error: failed to sync '%s': %s\n",
                LOG_FILENAME, strerror(errno));
        goto cleanup;
    }

    status = EXIT_SUCCESS;

cleanup:
    /*
     * 10. Close the descriptor. This also releases the lock. close() can
     *     report delayed write errors, so its result is checked too.
     */
    if (fd != -1) {
        if (close(fd) == -1) {
            fprintf(stderr, "Error: failed to close '%s': %s\n",
                    LOG_FILENAME, strerror(errno));
            status = EXIT_FAILURE;
        }
    }

    if (status == EXIT_SUCCESS) {
        printf("Log entry recorded.\n");
    }

    return status;
}