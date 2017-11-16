
#ifndef _WIFISESSIONCALLBACK_H_
#define _WIFISESSIONCALLBACK_H_

#include <wifipcap.h>

// XXX TODO: IMPLEMENT ME! :) [see wifitools/wifiprofiler/sample/main.cpp]

tyepdef enum { WIFI_SESSION_START, WIFI_SESSION_END, WIFI_SESSION_NONE } wifisession_t;

class WifiSessionCallbacks : public WifipcapCallbacks
{
public:
    // if a subclass reimplements these methods, it must callback these
    void PacketBegin(const struct timeval& t, const u_char *pkt, int len, int origlen);
    void PacketEnd();

    /**
     * Upon completing a packet, determine if this packet represents the
     * start or end of a session for a particular host (or neither).
     * A subclass should implement this method instead of PacketEnd().
     */
    virtual void PacketEnd(const MAC& host, wifisession_t status) = 0;

    void Handle80211(const struct timeval& t, u_int16_t fc, const MAC& sa, const MAC& da, const MAC& ra, const MAC& ta);

    // if a subclass reimplements these methods, it must callback these
    void Handle80211MgmtAssocRequest(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body);
    void Handle80211MgmtAssocResponse(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body);
    void Handle80211MgmtReassocRequest(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body);
    void Handle80211MgmtReassocResponse(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body);
    void Handle80211MgmtDisassoc(const struct timeval& t, const mgmt_header_t *hdr, const mgmt_body_t *body);
};


#endif
