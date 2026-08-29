#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned long long capability_value(const char *field) {
    FILE *stream = fopen("/proc/self/status", "r");
    char line[256];
    unsigned long long value = 0;
    if (stream == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), stream) != NULL) {
        if (strncmp(line, field, strlen(field)) == 0) {
            (void)sscanf(line + strlen(field), "%llx", &value);
            break;
        }
    }
    (void)fclose(stream);
    return value;
}

int main(void) {
    const unsigned long long effective = capability_value("CapEff:\t");
    const unsigned long long permitted = capability_value("CapPrm:\t");
    (void)printf(
        "{\"uid\":%lu,\"euid\":%lu,\"gid\":%lu,\"egid\":%lu,"
        "\"capabilities\":{\"effective\":%llu,\"permitted\":%llu}}\n",
        (unsigned long)getuid(), (unsigned long)geteuid(),
        (unsigned long)getgid(), (unsigned long)getegid(),
        effective, permitted
    );
    return 0;
}
