#pragma once

#include <Windows.h>

BOOL FindPatternReverse(PBYTE data, SIZE_T size, PBYTE pattern, SIZE_T patternSize, PBYTE* position);
BOOL FindPattern(PBYTE data, SIZE_T size, PBYTE pattern, SIZE_T patternSize, PBYTE* position);
SIZE_T FindAOBPattern(PBYTE address, SIZE_T size, PBYTE baseAddress, SIZE_T increment,
                      PBYTE pattern, PBYTE mask, SIZE_T patternSize, PBYTE* matches, SIZE_T matchesSize);
