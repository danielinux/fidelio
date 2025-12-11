/* Minimal syscall stubs to satisfy newlib when running baremetal on RP2040. */
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

int _close(int fd)
{
    (void)fd;
    errno = ENOSYS;
    return -1;
}

int _gettimeofday(struct timeval *tv, void *tz)
{
    (void)tz;
    if (tv) {
        tv->tv_sec = 0;
        tv->tv_usec = 0;
    }
    errno = ENOSYS;
    return -1;
}

off_t _lseek(int fd, off_t offset, int whence)
{
    (void)fd;
    (void)offset;
    (void)whence;
    errno = ENOSYS;
    return (off_t)-1;
}
