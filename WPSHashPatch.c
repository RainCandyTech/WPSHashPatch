#include <Windows.h>
#include <string.h>
#include <stdio.h>
#include "PatternUtil.h"

BOOL ReplaceBytes(PBYTE data, DWORD size) {
#ifdef _WIN64
    // ---------- 64位原补丁 ----------
    BYTE anchorPattern[] = { 0x63, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x02, 0x00, 0x00, 0x73 };
    BYTE anchorMask[] = { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00 };
    BYTE replacementPattern[] = { 0x48, 0x89, 0x5C, 0x24, 0x10 };
    BYTE replacement[] = { 0x48, 0x31, 0xC0, 0xC3, 0xFF };

    PBYTE position = NULL;
    PBYTE matches[2];

    // 以特征码模糊查找目标地址（仅锚点定位）
    if (FindAOBPattern(data, size, 0, 1, anchorPattern, anchorMask, sizeof(anchorPattern), matches, 2) != 1) {
        return FALSE;
    }

    // 从锚点向前逆向搜索原始函数起始字节（限制在 1024 字节内）
    if (!FindPatternReverse(data, (SIZE_T)matches[0], replacementPattern, sizeof(replacementPattern), &position)) {
        return FALSE;
    }

    // 检查搜索到的位置是否在锚点前 1024 字节内
    if (matches[0] - position > 1024) {
        return FALSE;
    }

    // 检查是否已打补丁（比较当前位置是否为 replacement 内容）
    if (memcmp(position, replacement, sizeof(replacement)) == 0) {
        // 已打补丁，视为成功
        return TRUE;
    }

    // 执行替换
    memcpy(position, replacement, sizeof(replacement));
    return TRUE;

#else
    // ---------- 新增：修补 ensureOemFileValid 以防止 oem.ini 被删除 ----------
    // 特征码：6a 01 57 e8 ?? ?? ?? ?? 8d 45 d4 6a 01 50 e8 ?? ?? ?? ??
    // 匹配 ensureOemFileValid 中连续两次调用 DeleteFileW 包装函数的机器码特征
    {
        BYTE delPattern[] = {
            0x6a, 0x01, 0x57, 0xe8, 0x00, 0x00, 0x00, 0x00,
            0x8d, 0x45, 0xd4, 0x6a, 0x01, 0x50, 0xe8, 0x00,
            0x00, 0x00, 0x00
        };
        // 0xFF 表示必须精确匹配，0x00 表示通配符 (因为 call 指令的相对偏移在不同版本可能会变)
        BYTE delMask[] = {
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
            0xFF, 0xFF, 0xFF
        };
        PBYTE delMatches[1];

        // 搜索特征码
        if (FindAOBPattern(data, size, 0, 1, delPattern, delMask, sizeof(delPattern), delMatches, 1) > 0) {
            // 获取特征码在内存中的实际指针地址
            PBYTE delPos = data + (SIZE_T)delMatches[0];

            // NOP 掉第一次文件删除调用 (替换 5 字节的 call 指令为 0x90 NOP)
            if (delPos[3] == 0xe8 && delPos[3] != 0x90) {
                memset(delPos + 3, 0x90, 5);
            }

            // NOP 掉第二次文件删除调用 (替换 5 字节的 call 指令为 0x90 NOP)
            if (delPos[14] == 0xe8 && delPos[14] != 0x90) {
                memset(delPos + 14, 0x90, 5);
            }
        }
    }

    // ---------- 原有的32位补丁 ----------
    BYTE anchorPattern[] = { 0x00, 0x02, 0x00, 0x00, 0x73, 0xFF, 0x56 };
    BYTE anchorMask[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00 };
    BYTE replacementPattern[] = { 0x53, 0x8B, 0xDC };
    BYTE replacement[] = { 0x31, 0xC0, 0xC3, 0xFF };

    PBYTE position = NULL;
    PBYTE matches[2];

    // 以特征码模糊查找目标地址（仅锚点定位）
    if (FindAOBPattern(data, size, 0, 1, anchorPattern, anchorMask, sizeof(anchorPattern), matches, 2) != 1) {
        return FALSE;
    }

    // 从锚点向前逆向搜索原始函数起始字节（限制在 1024 字节内）
    if (!FindPatternReverse(data, (SIZE_T)matches[0], replacementPattern, sizeof(replacementPattern), &position)) {
        return FALSE;
    }

    // 检查搜索到的位置是否在锚点前 1024 字节内
    if (matches[0] - position > 1024) {
        return FALSE;
    }

    // 检查是否已打补丁（比较当前位置是否为 replacement 内容）
    if (memcmp(position, replacement, sizeof(replacement)) == 0) {
        // 已打补丁，视为成功
        return TRUE;
    }

    // 执行替换
    memcpy(position, replacement, sizeof(replacement));
    return TRUE;
#endif
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
#ifdef _WIN64
        puts("Usage: WPSHashPatch64 <krt.dll>");
#else
        puts("Usage: WPSHashPatch32 <krt.dll>");
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

    BOOL success = ReplaceBytes(data, fileSize);
    UnmapViewOfFile(data);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    if (!success) {
        puts("Pattern not found.");
        return 1;
    }
    return 0;
}
