#include <string.h>
#include "PatternUtil.h"

BOOL FindPatternReverse(PBYTE data, SIZE_T size, PBYTE pattern, SIZE_T patternSize, PBYTE* position) {
    for (SIZE_T i = size - patternSize; i != (SIZE_T) -1; i--) {
        if (memcmp(data + i, pattern, patternSize) == 0) {
            *position = data + i;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL FindPattern(PBYTE data, SIZE_T size, PBYTE pattern, SIZE_T patternSize, PBYTE* position) {
    for (SIZE_T i = 0; i < size - patternSize; i++) {
        if (memcmp(data + i, pattern, patternSize) == 0) {
            *position = data + i;
            return TRUE;
        }
    }
    return FALSE;
}

SIZE_T FindAOBPattern(PBYTE address, SIZE_T size, PBYTE baseAddress, SIZE_T increment,
                      PBYTE pattern, PBYTE mask, SIZE_T patternSize, PBYTE* matches, SIZE_T matchesSize) {
    SIZE_T count = 0;
    for (SIZE_T i = 0; i < size; i += increment) {
        BOOL found = TRUE;
        for (SIZE_T k = 0; k < patternSize; k++) {
            if (mask[k] != 0xff && pattern[k] != address[i + k]) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            matches[count++] = baseAddress + i;
            if (count >= matchesSize) {
                return count;
            }
        }
    }
    return count;
}
