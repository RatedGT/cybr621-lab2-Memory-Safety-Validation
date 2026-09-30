/*
 * userlog.c - Securely append a username and log message to userlog.txt
 *
 * Usage:   ./userlog <username> <message>
 * Build:   gcc -std=c11 -Wall -Wextra -Werror -pedantic -O2 \
 *              -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie \
 *              -o userlog userlog.c
 *
 * Security measures:
 *   - Exact argument count check; NULL and length checks on every input.
 *   - Username restricted to a whitelist: [A-Za-z0-9._-], 1-32 chars,
 *     and it may not start with '-'.
 *   - Message restricted to printable ASCII (0x20-0x7E), 1-512 chars.
 *     This blocks newline/control-character log injection and terminal
 *     escape sequences.
 *   - Lengths measured with strnlen() so unterminated or huge inputs
 *     can't cause over-reads.
 *   - Log line built with snprintf() into a fixed buffer, with an explicit
 *     truncation check. No strcpy/strcat/sprintf/gets.
 *   - File opened with open() using O_APPEND | O_NOFOLLOW | O_CLOEXEC.
 *     Permissions are 0600 and the umask is restrictive.
 *   - fstat() confirms the target is a regular file owned by the caller
 *     with a single hard link. This defeats symlink and hard-link attacks.
 *   - An exclusive advisory lock (flock) prevents interleaved writes.
 *   - Every write, fsync, lock, and close result is checked. Partial
 *     writes and EINTR are handled.
 */

#define _GNU_SOURCE             /* O_NOFOLLOW, O_CLOEXEC, flock() on Linux */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ---- Configuration limits ---------------------------------------------- */
#define LOG_FILE            "userlog.txt"
#define MAX_USERNAME_LEN    32U     /* max characters in a username          */
#define MAX_MESSAGE_LEN     512U    /* max characters in a log message       */
#define TIMESTAMP_LEN       32U     /* buffer for ISO-8601 UTC timestamp     */
#define LINE_BUF_LEN        1024U   /* fits timestamp + user + msg + format  */

/* ---- Input validation -------------------------------------------------- */

/*
 * validate_username
 *   Accepts only [A-Za-z0-9._-], length 1..MAX_USERNAME_LEN, and the name
 *   may not start with '-'. Explicit character ranges are used instead of
 *   isalnum() so the result never depends on the current locale.
 *   Returns 0 if valid, -1 otherwise.
 */
static int validate_username(const char *user)
{
    size_t len;
    size_t i;

    if (user == NULL) {
        return -1;
    }

    /* strnlen bounds the scan; a result > MAX means "too long". */
    len = strnlen(user, MAX_USERNAME_LEN + 1U);
    if (len == 0U || len > MAX_USERNAME_LEN) {
        return -1;
    }

    if (user[0] == '-') {
        return -1;
    }

    for (i = 0U; i < len; i++) {
        unsigned char c = (unsigned char)user[i];
        int ok = (c >= 'a' && c <= 'z') ||
                 (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') ||
                 c == '_' || c == '-' || c == '.';
        if (!ok) {
            return -1;
        }
    }
    return 0;
}

/*
 * validate_message
 *   Accepts printable ASCII only (space through '~'), length
 *   1..MAX_MESSAGE_LEN. Newlines, carriage returns, tabs, escape sequences,
 *   and other control or non-ASCII bytes are rejected. This prevents forged
 *   log entries and terminal injection.
 *   Returns 0 if valid, -1 otherwise.
 */
static int validate_message(const char *msg)
{
    size_t len;
    size_t i;

    if (msg == NULL) {
        return -1;
    }

    len = strnlen(msg, MAX_MESSAGE_LEN + 1U);
    if (len == 0U || len > MAX_MESSAGE_LEN) {
        return -1;
    }

    for (i = 0U; i < len; i++) {
        unsigned char c = (unsigned char)msg[i];
        if (c < 0x20U || c > 0x7EU) {
            return -1;
        }
    }
    return 0;
}

/* ---- I/O helpers ------------------------------------------------------- */

/*
 * write_all
 *   Writes exactly len bytes, retrying on partial writes and EINTR.
 *   Returns 0 on success, -1 on error (errno set).
 */
static int write_all(int fd, const char *buf, size_t len)
{
    size_t off = 0U;

    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;               /* interrupted by a signal: retry */
            }
            return -1;
        }
        if (n == 0) {                   /* should not happen on a regular file */
            errno = EIO;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/*
 * lock_file
 *   Acquires an exclusive advisory lock, retrying on EINTR.
 *   Returns 0 on success, -1 on error.
 */
static int lock_file(int fd)
{
    while (flock(fd, LOCK_EX) != 0) {
        if (errno != EINTR) {
            return -1;
        }
    }
    return 0;
}

/*
 * make_timestamp
 *   Writes the current UTC time as YYYY-MM-DDTHH:MM:SSZ into buf.
 *   Returns 0 on success, -1 on error.
 */
static int make_timestamp(char *buf, size_t buflen)
{
    time_t now;
    struct tm tmv;

    if (buf == NULL || buflen == 0U) {
        return -1;
    }

    now = time(NULL);
    if (now == (time_t)-1) {
        return -1;
    }

    /* gmtime_r is the reentrant form; it avoids a shared static buffer. */
    if (gmtime_r(&now, &tmv) == NULL) {
        return -1;
    }

    if (strftime(buf, buflen, "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0U) {
        return -1;
    }
    return 0;
}

/* ---- Main -------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    const char *username;
    const char *message;
    char timestamp[TIMESTAMP_LEN];
    char line[LINE_BUF_LEN];
    int line_len;
    int fd = -1;
    int status = EXIT_FAILURE;
    struct stat st;

    /* Files this process creates get owner-only permissions. */
    (void)umask(077);

    /* 1. Argument count. A fixed program name in the usage text avoids
     *    echoing untrusted argv[0] content. */
    if (argc != 3 || argv == NULL) {
        fprintf(stderr, "Usage: userlog <username> <message>\n");
        return EXIT_FAILURE;
    }

    username = argv[1];
    message  = argv[2];

    /* 2. Validate inputs before touching the filesystem. */
    if (validate_username(username) != 0) {
        fprintf(stderr,
                "Error: invalid username (1-%u chars, [A-Za-z0-9._-], "
                "must not start with '-').\n", MAX_USERNAME_LEN);
        return EXIT_FAILURE;
    }

    if (validate_message(message) != 0) {
        fprintf(stderr,
                "Error: invalid message (1-%u printable ASCII chars, "
                "no control characters).\n", MAX_MESSAGE_LEN);
        return EXIT_FAILURE;
    }

    /* 3. Build the log line in a bounded buffer and check for truncation. */
    if (make_timestamp(timestamp, sizeof(timestamp)) != 0) {
        fprintf(stderr, "Error: unable to obtain current time.\n");
        return EXIT_FAILURE;
    }

    line_len = snprintf(line, sizeof(line), "%s | user=%s | msg=%s\n",
                        timestamp, username, message);
    if (line_len < 0 || (size_t)line_len >= sizeof(line)) {
        fprintf(stderr, "Error: log entry could not be formatted.\n");
        return EXIT_FAILURE;
    }

    /* 4. Open the log file safely.
     *    O_APPEND   - each write goes atomically to the end of the file
     *    O_CREAT    - create the file if missing (mode 0600)
     *    O_NOFOLLOW - refuse to open if the path is a symbolic link
     *    O_CLOEXEC  - don't leak the descriptor to child processes */
    fd = open(LOG_FILE,
              O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
              S_IRUSR | S_IWUSR);
    if (fd < 0) {
        fprintf(stderr, "Error: cannot open %s: %s\n",
                LOG_FILE, strerror(errno));
        return EXIT_FAILURE;
    }

    /* 5. Check the opened descriptor itself (not the path) so the check
     *    can't race against the file being swapped out. */
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "Error: cannot stat %s: %s\n",
                LOG_FILE, strerror(errno));
        goto cleanup;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: %s is not a regular file.\n", LOG_FILE);
        goto cleanup;
    }
    if (st.st_nlink != 1) {
        fprintf(stderr, "Error: %s has multiple hard links; refusing.\n",
                LOG_FILE);
        goto cleanup;
    }
    if (st.st_uid != geteuid()) {
        fprintf(stderr, "Error: %s is not owned by the current user.\n",
                LOG_FILE);
        goto cleanup;
    }

    /* 6. Take an exclusive lock so concurrent runs don't interleave. */
    if (lock_file(fd) != 0) {
        fprintf(stderr, "Error: cannot lock %s: %s\n",
                LOG_FILE, strerror(errno));
        goto cleanup;
    }

    /* 7. Write the entry, handling partial writes. */
    if (write_all(fd, line, (size_t)line_len) != 0) {
        fprintf(stderr, "Error: write to %s failed: %s\n",
                LOG_FILE, strerror(errno));
        goto cleanup;
    }

    /* 8. Flush to stable storage so the entry survives a crash. */
    if (fsync(fd) != 0) {
        fprintf(stderr, "Error: fsync on %s failed: %s\n",
                LOG_FILE, strerror(errno));
        goto cleanup;
    }

    status = EXIT_SUCCESS;

cleanup:
    /* 9. Close the descriptor and check the result, since close() can
     *    report deferred write errors. Closing also releases the lock. */
    if (fd >= 0) {
        if (close(fd) != 0) {
            fprintf(stderr, "Error: close on %s failed: %s\n",
                    LOG_FILE, strerror(errno));
            status = EXIT_FAILURE;
        }
    }

    /* Clear the formatted line from the stack before exiting. */
    memset(line, 0, sizeof(line));

    return status;
}