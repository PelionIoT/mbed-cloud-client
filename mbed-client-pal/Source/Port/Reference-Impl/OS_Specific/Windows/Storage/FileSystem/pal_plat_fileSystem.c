/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "pal.h"
#include "pal_plat_fileSystem.h"

static palStatus_t fs_error(DWORD error)
{
    switch (error) {
        case ERROR_FILE_NOT_FOUND: return PAL_ERR_FS_NO_FILE;
        case ERROR_PATH_NOT_FOUND: return PAL_ERR_FS_NO_PATH;
        case ERROR_ACCESS_DENIED: return PAL_ERR_FS_ACCESS_DENIED;
        case ERROR_SHARING_VIOLATION: case ERROR_LOCK_VIOLATION: return PAL_ERR_FS_BUSY;
        case ERROR_ALREADY_EXISTS: case ERROR_FILE_EXISTS: return PAL_ERR_FS_NAME_ALREADY_EXIST;
        case ERROR_DISK_FULL: case ERROR_HANDLE_DISK_FULL: return PAL_ERR_FS_INSUFFICIENT_SPACE;
        case ERROR_INVALID_HANDLE: return PAL_ERR_FS_BAD_FD;
        case ERROR_DIR_NOT_EMPTY: return PAL_ERR_FS_DIR_NOT_EMPTY;
        case ERROR_FILENAME_EXCED_RANGE: return PAL_ERR_FS_FILENAME_LENGTH;
        case ERROR_INVALID_NAME: case ERROR_NO_UNICODE_TRANSLATION: return PAL_ERR_FS_INVALID_FILE_NAME;
        case ERROR_INVALID_PARAMETER: return PAL_ERR_FS_INVALID_ARGUMENT;
        case ERROR_TOO_MANY_OPEN_FILES: return PAL_ERR_FS_TOO_MANY_OPEN_FD;
        case ERROR_NOT_ENOUGH_MEMORY: return PAL_ERR_NO_MEMORY;
        default: return PAL_ERR_FS_ERROR;
    }
}

/* PAL strings are UTF-8; do not make credential paths depend on the machine's
 * ANSI code page. The PAL layer above retains its existing path-size limits. */
static wchar_t *wide_path(const char *path)
{
    int length;
    wchar_t *wide;
    if (!path || !*path) { SetLastError(ERROR_INVALID_NAME); return NULL; }
    length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    if (!length) return NULL;
    wide = malloc((size_t)length * sizeof(*wide));
    if (!wide) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, length)) {
        DWORD error = GetLastError();
        free(wide);
        SetLastError(error);
        return NULL;
    }
    return wide;
}

palStatus_t pal_plat_fsMkdir(const char *path)
{
    wchar_t *wide = wide_path(path);
    palStatus_t status;
    if (!wide) return fs_error(GetLastError());
    status = CreateDirectoryW(wide, NULL) ? PAL_SUCCESS : fs_error(GetLastError());
    free(wide);
    return status;
}

palStatus_t pal_plat_fsRmdir(const char *path)
{
    wchar_t *wide = wide_path(path);
    palStatus_t status;
    if (!wide) return fs_error(GetLastError());
    status = RemoveDirectoryW(wide) ? PAL_SUCCESS : fs_error(GetLastError());
    free(wide);
    return status;
}

palStatus_t pal_plat_fsFopen(const char *path, pal_fsFileMode_t mode, palFileDescriptor_t *fd)
{
    wchar_t *wide;
    HANDLE file;
    DWORD access = GENERIC_READ, creation, error;
    if (!fd) return PAL_ERR_FS_INVALID_ARGUMENT;
    *fd = 0;
    switch (mode) {
        case PAL_FS_FLAG_READONLY: creation = OPEN_EXISTING; break;
        case PAL_FS_FLAG_READWRITE: creation = OPEN_EXISTING; access |= GENERIC_WRITE; break;
        case PAL_FS_FLAG_READWRITEEXCLUSIVE: creation = CREATE_NEW; access |= GENERIC_WRITE; break;
        case PAL_FS_FLAG_READWRITETRUNC: creation = CREATE_ALWAYS; access |= GENERIC_WRITE; break;
        default: return PAL_ERR_FS_INVALID_OPEN_FLAGS;
    }
    wide = wide_path(path);
    if (!wide) return fs_error(GetLastError());
    /* Inherit storage-directory ACLs. Writable handles deny concurrent writers;
     * write-through avoids reporting successful credential writes still held
     * solely in the Windows file cache. */
    file = CreateFileW(wide, access, FILE_SHARE_READ, NULL, creation,
        FILE_ATTRIBUTE_NORMAL | ((access & GENERIC_WRITE) ? FILE_FLAG_WRITE_THROUGH : 0), NULL);
    error = GetLastError();
    free(wide);
    /* PAL open follows ENOENT semantics for a missing file or parent. ESFS
     * probes BACKUP/FR/fr_on before the FR directory exists on first boot. */
    if (file == INVALID_HANDLE_VALUE)
        return error == ERROR_PATH_NOT_FOUND ? PAL_ERR_FS_NO_FILE : fs_error(error);
    *fd = (palFileDescriptor_t)file;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_fsFclose(palFileDescriptor_t *fd)
{
    if (!fd || !*fd) return PAL_ERR_FS_BAD_FD;
    if (!CloseHandle((HANDLE)*fd)) return fs_error(GetLastError());
    *fd = 0;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_fsFread(palFileDescriptor_t *fd, void *buffer, size_t size, size_t *actual)
{
    if (!actual) return PAL_ERR_FS_INVALID_ARGUMENT;
    *actual = 0;
    if (!fd || !*fd) return PAL_ERR_FS_BAD_FD;
    if (!buffer && size) return PAL_ERR_FS_BUFFER_ERROR;
    while (*actual < size) {
        DWORD done = 0;
        DWORD chunk = size - *actual > MAXDWORD ? MAXDWORD : (DWORD)(size - *actual);
        if (!ReadFile((HANDLE)*fd, (char *)buffer + *actual, chunk, &done, NULL)) return fs_error(GetLastError());
        *actual += done;
        if (done < chunk) break;
    }
    return PAL_SUCCESS;
}

palStatus_t pal_plat_fsFwrite(palFileDescriptor_t *fd, const void *buffer, size_t size, size_t *actual)
{
    if (!actual) return PAL_ERR_FS_INVALID_ARGUMENT;
    *actual = 0;
    if (!fd || !*fd) return PAL_ERR_FS_BAD_FD;
    if (!buffer && size) return PAL_ERR_FS_BUFFER_ERROR;
    while (*actual < size) {
        DWORD done = 0;
        DWORD chunk = size - *actual > MAXDWORD ? MAXDWORD : (DWORD)(size - *actual);
        if (!WriteFile((HANDLE)*fd, (const char *)buffer + *actual, chunk, &done, NULL)) return fs_error(GetLastError());
        *actual += done;
        if (done < chunk) return PAL_ERR_FS_INSUFFICIENT_SPACE;
    }
    return PAL_SUCCESS;
}

palStatus_t pal_plat_fsFseek(palFileDescriptor_t *fd, off_t offset, pal_fsOffset_t whence)
{
    DWORD method;
    LARGE_INTEGER distance;
    if (!fd || !*fd) return PAL_ERR_FS_BAD_FD;
    switch (whence) {
        case PAL_FS_OFFSET_SEEKSET: method = FILE_BEGIN; break;
        case PAL_FS_OFFSET_SEEKCUR: method = FILE_CURRENT; break;
        case PAL_FS_OFFSET_SEEKEND: method = FILE_END; break;
        default: return PAL_ERR_FS_OFFSET_ERROR;
    }
    distance.QuadPart = offset;
    return SetFilePointerEx((HANDLE)*fd, distance, NULL, method) ? PAL_SUCCESS : PAL_ERR_FS_OFFSET_ERROR;
}

palStatus_t pal_plat_fsFtell(palFileDescriptor_t *fd, off_t *position)
{
    LARGE_INTEGER zero = {0}, current;
    if (!position) return PAL_ERR_FS_INVALID_ARGUMENT;
    *position = 0;
    if (!fd || !*fd) return PAL_ERR_FS_BAD_FD;
    if (!SetFilePointerEx((HANDLE)*fd, zero, &current, FILE_CURRENT)) return fs_error(GetLastError());
    /* MSVC off_t is 32-bit even on x64. Never silently truncate its result. */
    if ((LONGLONG)(off_t)current.QuadPart != current.QuadPart) return PAL_ERR_FS_OFFSET_ERROR;
    *position = (off_t)current.QuadPart;
    return PAL_SUCCESS;
}

palStatus_t pal_plat_fsUnlink(const char *path)
{
    wchar_t *wide = wide_path(path);
    palStatus_t status;
    if (!wide) return fs_error(GetLastError());
    status = DeleteFileW(wide) ? PAL_SUCCESS : fs_error(GetLastError());
    free(wide);
    return status;
}

static wchar_t *join_path(const wchar_t *directory, const wchar_t *name)
{
    size_t a = wcslen(directory), b = wcslen(name);
    wchar_t *result = malloc((a + b + 2) * sizeof(*result));
    if (result) {
        memcpy(result, directory, a * sizeof(*result));
        result[a] = L'\\';
        memcpy(result + a + 1, name, (b + 1) * sizeof(*result));
    }
    return result;
}

/* The PAL contract is a flat operation: preserve subdirectories and reject
 * reparse-point roots/files rather than following a junction outside storage. */
static palStatus_t folder_files(const char *source, const char *destination)
{
    wchar_t *src = wide_path(source), *dst = NULL, *pattern = NULL;
    HANDLE find = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW data;
    palStatus_t status = PAL_SUCCESS;
    DWORD attributes;
    if (!src) return fs_error(GetLastError());
    attributes = GetFileAttributesW(src);
    if (attributes == INVALID_FILE_ATTRIBUTES) { status = fs_error(GetLastError()); goto done; }
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        status = PAL_ERR_FS_ACCESS_DENIED; goto done;
    }
    if (destination) {
        dst = wide_path(destination);
        if (!dst) { status = fs_error(GetLastError()); goto done; }
        attributes = GetFileAttributesW(dst);
        if (attributes == INVALID_FILE_ATTRIBUTES) { status = fs_error(GetLastError()); goto done; }
        if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            status = PAL_ERR_FS_ACCESS_DENIED; goto done;
        }
    }
    pattern = join_path(src, L"*");
    if (!pattern) { status = PAL_ERR_NO_MEMORY; goto done; }
    find = FindFirstFileW(pattern, &data);
    if (find == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        status = error == ERROR_FILE_NOT_FOUND ? PAL_SUCCESS : fs_error(error);
        goto done;
    }
    do {
        wchar_t *from, *to = NULL;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) { status = PAL_ERR_FS_ACCESS_DENIED; break; }
        from = join_path(src, data.cFileName);
        if (dst) to = join_path(dst, data.cFileName);
        if (!from || (dst && !to)) status = PAL_ERR_NO_MEMORY;
        else if (dst) {
            DWORD target = GetFileAttributesW(to);
            if (target != INVALID_FILE_ATTRIBUTES && (target & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
                status = PAL_ERR_FS_ACCESS_DENIED;
            } else if (!CopyFileW(from, to, FALSE)) status = fs_error(GetLastError());
        } else if (!DeleteFileW(from)) status = fs_error(GetLastError());
        free(from);
        free(to);
        if (status != PAL_SUCCESS) break;
    } while (FindNextFileW(find, &data));
    if (status == PAL_SUCCESS && GetLastError() != ERROR_NO_MORE_FILES) status = fs_error(GetLastError());
done:
    if (find != INVALID_HANDLE_VALUE) FindClose(find);
    free(pattern);
    free(src);
    free(dst);
    return status;
}

palStatus_t pal_plat_fsRmFiles(const char *path) { return folder_files(path, NULL); }
palStatus_t pal_plat_fsCpFolder(const char *source, char *destination)
{
    if (!destination) return PAL_ERR_FS_INVALID_ARGUMENT;
    return folder_files(source, destination);
}
const char *pal_plat_fsGetDefaultRootFolder(pal_fsStorageID_t partition)
{
    if (partition == PAL_FS_PARTITION_PRIMARY) return PAL_FS_MOUNT_POINT_PRIMARY;
    if (partition == PAL_FS_PARTITION_SECONDARY) return PAL_FS_MOUNT_POINT_SECONDARY;
    return NULL;
}
size_t pal_plat_fsSizeCheck(const char *string) { return string ? strlen(string) : 0; }
palStatus_t pal_plat_fsFormat(pal_fsStorageID_t partition)
{
    (void)partition;
    /* PAL's default shared partition must never format a Windows volume. */
    return PAL_ERR_NOT_SUPPORTED;
}
