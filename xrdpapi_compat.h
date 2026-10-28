#ifndef RDPEWA_XRDPAPI_COMPAT_H
#define RDPEWA_XRDPAPI_COMPAT_H

/*
 * ABI declarations verified against xrdp v0.9.24 xrdpapi/xrdpapi.h.
 * Ubuntu's installed xrdp package provides the library but not that header.
 * These are xrdp's signatures, not the Win32 WTS API signatures.
 */
#define WTS_CURRENT_SESSION 0xffffffffU
#define WTS_CHANNEL_OPTION_DYNAMIC 1U

void *WTSVirtualChannelOpenEx(unsigned int session_id, const char *name,
                            unsigned int flags);
int WTSVirtualChannelWrite(void *channel, const char *buffer,
                          unsigned int length, unsigned int *written);
int WTSVirtualChannelRead(void *channel, unsigned int timeout_ms,
                         char *buffer, unsigned int size, unsigned int *read);
int WTSVirtualChannelClose(void *channel);

#endif
