#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/md5.h>

#define MAX_LINE 1024
#define MD5_HEX_LEN 32
#define PASS_LEN 80

// Trim newline
static void trim_newline(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r' || isspace((unsigned char)s[n-1]))) {
        s[n-1] = '\0';
        --n;
    }
}

// Compute MD5 hex for plaintext into out_hex (must be at least 33 bytes)
static void compute_md5_hex(const char *plaintext, char out_hex[MD5_HEX_LEN + 1]) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((const unsigned char *)plaintext, strlen(plaintext), digest);

    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(out_hex + (i * 2), "%02x", digest[i]);
    }
    out_hex[MD5_HEX_LEN] = '\0';
}

char * tryWord(char * plaintext, char * hashFilename)
{
    if (!plaintext || !hashFilename) return NULL;

    char candidate_hex[MD5_HEX_LEN + 1];
    compute_md5_hex(plaintext, candidate_hex);

    FILE *hf = fopen(hashFilename, "r");
    if (!hf) {
        perror("tryWord: fopen hash file");
        return NULL;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), hf)) {
        trim_newline(line);
        if (line[0] == '\0') continue;

        // normalize to lowercase
        for (char *p = line; *p; ++p) *p = tolower((unsigned char)*p);

        if (strcmp(candidate_hex, line) == 0) {
            char *found = strdup(line);
            fclose(hf);
            return found;
        }
    }

    fclose(hf);
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        return 1;
    }

    char *hashFile = argv[1];
    char *dictFile = argv[2];

    // Test tryWord with "hello"
    char *found = tryWord("hello", hashFile);
    if (found) {
        printf("%s %s\n", found, "hello");
        free(found);
    } else {
        char hello_hex[MD5_HEX_LEN + 1];
        compute_md5_hex("hello", hello_hex);
        printf("%s %s\n", hello_hex, "hello");
    }

    // Open dictionary and try to crack hashes
    FILE *df = fopen(dictFile, "r");
    if (!df) {
        perror("fopen dictionary");
        return 2;
    }

    size_t cracked_count = 0;
    char wordbuf[PASS_LEN + 3];

    while (fgets(wordbuf, sizeof(wordbuf), df)) {
        trim_newline(wordbuf);
        if (wordbuf[0] == '\0') continue;

        char *res = tryWord(wordbuf, hashFile);
        if (res) {
            printf("%s %s\n", res, wordbuf);
            free(res);
            ++cracked_count;
        }
    }

    fclose(df);

    printf("%zu hashes cracked!\n", cracked_count);

    return 0;
}