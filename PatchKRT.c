#include <Windows.h>
#include <string.h>
#include <stdio.h>

BOOL findPatternForward(PBYTE data, SIZE_T size, PBYTE pattern, SIZE_T patternSize, PBYTE start, PBYTE* position) {
    for (SIZE_T i = start - data; i < size - patternSize; i++) {
        if (memcmp(data + i, pattern, patternSize) == 0) {
            *position = data + i;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL findPatternBackward(PBYTE data, SIZE_T size, PBYTE pattern, SIZE_T patternSize, PBYTE start, PBYTE* position) {
    for (SIZE_T i = start - data; i >= patternSize; i--) {
        if (memcmp(data + i - patternSize, pattern, patternSize) == 0) {
            *position = data + i - patternSize;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL replaceBytes(PBYTE data, DWORD size) {
    BYTE patternAnchor[] = { 0x00, 0x02, 0x00, 0x00, 0x73 };

#ifdef _WIN64
    BYTE pattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x10 };
    BYTE replacement[] = { 0x48, 0x31, 0xC0, 0xC3, 0xCC };
#else
    BYTE pattern[] = { 0x53, 0x8B, 0xDC };
    BYTE replacement[] = { 0x31, 0xC0, 0xC3 };
#endif

    PBYTE positionAnchor = NULL;
    PBYTE position = NULL;

    // Check if the replacement pattern already exists
    if (findPatternForward(data, size, replacement, sizeof(replacement), data, &positionAnchor)) {
        return FALSE;
    }

    // Find the first pattern
    if (findPatternForward(data, size, patternAnchor, sizeof(patternAnchor), data, &positionAnchor)) {
        // Find the second pattern before positionAnchor
        if (findPatternBackward(data, size, pattern, sizeof(pattern), positionAnchor, &position)) {
            memcpy(position, replacement, sizeof(replacement));
            return TRUE;
        }
    }

    return FALSE;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
#ifdef _WIN64
        puts("Usage: PatchKRT64 <krt.dll>");
#else
        puts("Usage: PatchKRT32 <krt.dll>");
#endif
        return 1;
    }

    HANDLE hFile = CreateFileW(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        puts("Unable to open file.");
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READWRITE, 0, fileSize, NULL);
    if (hMapping == NULL) {
        puts("Unable to create file mapping.");
        CloseHandle(hFile);
        return 1;
    }

    PBYTE data = (PBYTE) MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, fileSize);
    if (data == NULL) {
        puts("Unable to map view of file.");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 1;
    }

    BOOL success = replaceBytes(data, fileSize);
    UnmapViewOfFile(data);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    if (!success) {
        puts("Pattern not found.");
        return 1;
    }
    return 0;
}
