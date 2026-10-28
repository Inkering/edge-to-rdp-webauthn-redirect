#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "xrdpapi_compat.h"

/* CBOR {"command": 8, "flags": 0, "timeout": 0,
 *       "transactionId": h'00000000000000000000000000000000'}.
 * No length prefix or CHANNEL_PDU_HEADER on xrdp's DVC API.
 */
static const unsigned char request[] = {
    0xa4, 0x67, 'c', 'o', 'm', 'm', 'a', 'n', 'd', 0x08,
    0x65, 'f', 'l', 'a', 'g', 's', 0x00,
    0x67, 't', 'i', 'm', 'e', 'o', 'u', 't', 0x00,
    0x6d, 't', 'r', 'a', 'n', 's', 'a', 'c', 't', 'i', 'o', 'n', 'I', 'd',
    0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

enum { USAGE_ERROR = 2, OPEN_ERROR, WRITE_ERROR, READ_ERROR,
       PROTOCOL_ERROR, HRESULT_ERROR, VERSION_ERROR, CLOSE_ERROR };
static volatile sig_atomic_t stage;

static void interrupted(int sig)
{
    const char *message;
    if (sig == SIGALRM)
    {
        switch (stage)
        {
            case 0:
                message = "ERROR open: deadline exceeded\n";
                break;
            case 1:
                message = "ERROR write: deadline exceeded\n";
                break;
            case 2:
                message = "ERROR read: deadline exceeded\n";
                break;
            default:
                message = "ERROR close: deadline exceeded\n";
                break;
        }
    }
    else
    {
        message = "ERROR interrupted: terminating probe\n";
    }
    size_t length = 0;
    while (message[length])
        ++length;
    ssize_t written = write(STDERR_FILENO, message, length);
    (void)written;
    /* libxrdpapi is not signal-safe; process exit closes its socket. */
    _exit(sig == SIGALRM ? 124 : 128 + sig);
}

static uint32_t le32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

int main(int argc, char **argv)
{
    unsigned int seconds = 10;
    if (argc == 2)
    {
        char *end;
        errno = 0;
        unsigned long value = strtoul(argv[1], &end, 10);
        if (errno || end == argv[1] || *end || value < 1 || value > 120)
        {
            fprintf(stderr, "Usage: %s [deadline-seconds: 1..120]\n", argv[0]);
            return USAGE_ERROR;
        }
        seconds = (unsigned int)value;
    }
    else if (argc != 1)
    {
        fprintf(stderr, "Usage: %s [deadline-seconds: 1..120]\n", argv[0]);
        return USAGE_ERROR;
    }
    if (!getenv("DISPLAY") || !*getenv("DISPLAY"))
    {
        fprintf(stderr, "ERROR session: DISPLAY is unset; run inside the xrdp desktop\n");
        return USAGE_ERROR;
    }
    struct sigaction action = {0};
    action.sa_handler = interrupted;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, NULL) ||
        sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL))
    {
        perror("ERROR installing signal handlers");
        return USAGE_ERROR;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(seconds);
    printf("Prerequisite: Windows .rdp must contain redirectwebauthn:i:1; "
           "reconnect after editing.\n");
    printf("Opening dynamic WebAuthN_Channel via WTSVirtualChannelOpenEx "
           "(total deadline %u s)\n", seconds);
    errno = 0;
    void *channel = WTSVirtualChannelOpenEx(WTS_CURRENT_SESSION,
                                           "WebAuthN_Channel",
                                           WTS_CHANNEL_OPTION_DYNAMIC);
    if (!channel)
    {
        fprintf(stderr, "ERROR open: WTSVirtualChannelOpenEx returned NULL "
                "(errno=%d; xrdp does not guarantee a useful errno). "
                "Check chansrv/client diagnostics, drdynvc, Windows policy "
                "and redirectwebauthn:i:1.\n", errno);
        return OPEN_ERROR;
    }
    printf("Channel opened; this is NOT proof of WebAuthn support.\n");
    int result = 0;
    stage = 1;
    for (;;)
    {
        unsigned int written = 0;
        errno = 0;
        int ok = WTSVirtualChannelWrite(channel, (const char *)request,
                                        sizeof(request), &written);
        if (!ok || (written != 0 && written != sizeof(request)))
        {
            fprintf(stderr, "ERROR write: result=%d bytes=%u/%zu errno=%d; "
                    "partial DVC requests cannot be retried as new messages\n",
                    ok, written, sizeof(request), errno);
            result = WRITE_ERROR;
            goto close_channel;
        }
        if (written == sizeof(request))
            break;
        struct timespec pause = {0, 10000000};
        nanosleep(&pause, NULL);
    }
    printf("Sent API_VERSION command=8 (%zu CBOR bytes).\n", sizeof(request));
    stage = 2;
    unsigned char response[9];
    unsigned int used = 0;
    uint32_t hresult = 0;
    for (;;)
    {
        unsigned int count = 0;
        errno = 0;
        int ok = WTSVirtualChannelRead(channel, 100, (char *)response + used,
                                       sizeof(response) - used, &count);
        if (!ok)
        {
            fprintf(stderr, "ERROR read: channel disconnected or read failed "
                    "after %u bytes (errno=%d)\n", used, errno);
            result = READ_ERROR;
            goto close_channel;
        }
        if (count > sizeof(response) - used)
        {
            fprintf(stderr, "ERROR read: library returned an invalid byte count\n");
            result = PROTOCOL_ERROR;
            goto close_channel;
        }
        used += count;
        if (used >= 4)
        {
            hresult = le32(response);
            if (hresult & UINT32_C(0x80000000))
            {
                fprintf(stderr, "ERROR API_VERSION: HRESULT=0x%08" PRIx32 "\n",
                        hresult);
                result = HRESULT_ERROR;
                goto close_channel;
            }
        }
        if (used > 8)
        {
            fprintf(stderr, "ERROR protocol: API_VERSION response exceeds 8 bytes\n");
            result = PROTOCOL_ERROR;
            goto close_channel;
        }
        if (used == 8)
            break;
    }
    uint32_t version = le32(response + 4);
    printf("API_VERSION response: HRESULT=0x%08" PRIx32 " version=%" PRIu32 "\n",
           hresult, version);
    if (version == 0)
    {
        fprintf(stderr, "ERROR version: API version 0 has no usable WebAuthn API\n");
        result = VERSION_ERROR;
    }

close_channel:
    stage = 3;
    if (!WTSVirtualChannelClose(channel))
    {
        fprintf(stderr, "ERROR close: WTSVirtualChannelClose failed\n");
        if (!result)
            result = CLOSE_ERROR;
    }
    alarm(0);
    if (!result)
        printf("API_VERSION exchange succeeded. YubiKey authentication, signature "
               "verification and Edge integration remain UNPROVEN.\n");
    return result;
}
