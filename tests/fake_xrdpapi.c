#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../xrdpapi_compat.h"

static unsigned int position;
static unsigned int writes;

static int mode(const char *name)
{
    const char *value = getenv("PROBE_TEST_MODE");
    return value && strcmp(value, name) == 0;
}

void *WTSVirtualChannelOpenEx(unsigned int session, const char *name,
                            unsigned int flags)
{
    if (session != WTS_CURRENT_SESSION || flags != WTS_CHANNEL_OPTION_DYNAMIC ||
        strcmp(name, "WebAuthN_Channel") != 0 || mode("open-error"))
        return NULL;
    if (mode("open-hang"))
        for (;;) pause();
    return &position;
}

int WTSVirtualChannelWrite(void *channel, const char *buffer,
                          unsigned int length, unsigned int *written)
{
    if (mode("write-hang"))
        for (;;) pause();
    if (channel != &position || length != 57 ||
        memcmp(buffer, "\xa4\x67" "command\x08", 10) != 0)
        return 0;
    if (mode("write-error"))
        return 0;
    *written = mode("partial-write") ? 1 : length;
    if (mode("retry-write") && writes++ == 0)
        *written = 0;
    return 1;
}

int WTSVirtualChannelRead(void *channel, unsigned int timeout_ms,
                         char *buffer, unsigned int size, unsigned int *count)
{
    unsigned char data[9] = {0, 0, 0, 0, 9, 0, 0, 0, 0};
    (void)timeout_ms;
    if (channel != &position || mode("read-error"))
        return 0;
    if (mode("read-hang"))
        for (;;) pause();
    if (mode("hresult"))
    {
        data[0] = 5;
        data[3] = 0x80;
    }
    if (mode("version-zero"))
        data[4] = 0;
    unsigned int length = mode("oversize") ? 9 : mode("hresult") ? 4 : 8;
    if (mode("truncated"))
        length = 6;
    if (position == length)
    {
        *count = 0;
        return 1;
    }
    *count = mode("fragmented") ? 1 : length - position;
    if (*count > size)
        *count = size;
    memcpy(buffer, data + position, *count);
    position += *count;
    return 1;
}

int WTSVirtualChannelClose(void *channel)
{
    if (channel != &position || mode("close-error"))
        return 0;
    return 1;
}
