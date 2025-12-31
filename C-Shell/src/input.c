#include "../include/input.h"

char* read_input() {
    static char input[4097];
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return NULL;
    }
    input[strcspn(input, "\n")] = 0;
    return input;
}
