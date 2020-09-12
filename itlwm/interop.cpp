//
//  interop.cpp
//  itlwm
//
//  Created by usrsse2 on 30.07.2020.
//  Copyright © 2020 钟先耀. All rights reserved.
//

#ifdef AIRPORT

#include "itlwm.hpp"

#include "types.h"
#include "kernel.h"

#include <IOKit/IOInterruptController.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/network/IONetworkMedium.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <net/ethernet.h>
#include "sha1.h"
#include <net80211/ieee80211_node.h>
#include <net80211/ieee80211_ioctl.h>

#include "interop.hpp"

OSDefineMetaClassAndStructors(ScanResult, OSObject)

static IOReturn sleep(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3) {
	itlwm *self = (itlwm*)target;
	self->disable();
	return kIOReturnSuccess;
}

static IOReturn wake(OSObject *target, void *arg0, void *arg1, void *arg2, void *arg3) {
	((itlwm*)target)->enable();
	return kIOReturnSuccess;
}

IOReturn sleepHandler( void * target, void * refCon,
                        UInt32 messageType, IOService * provider,
                        void * messageArgument, vm_size_t argSize)
{
	static bool first = true;
    itlwm *self = (itlwm*)target;
	switch (messageType)
    {
        case kIOMessageSystemWillPowerOff:
        case kIOMessageSystemWillRestart:
        case kIOMessageSystemWillSleep:
			self->getCommandGate()->attemptAction(sleep, self);
            break;
			
		case kIOMessageSystemHasPoweredOn:
			self->getCommandGate()->enable();
			self->getCommandGate()->runAction(wake);
			// fall through
		case kIOMessageSystemWillPowerOn:
	       break;
    }
	// on first notification after boot gRootDomain is still nullptr
	if (first) {
		first = false;
		XYLog("skipped acknowledgement for message %x\n", messageType);
		return kIOReturnSuccess;
	}
	acknowledgeSleepWakeNotification(refCon); // this method dereferences gRootDomain
	return kIOReturnSuccess;
}



bool ScanResult::init() {
	count = 0;
	networks = nullptr;

	if (!OSObject::init())
		return false;
	
	return true;
}

void ScanResult::free() {
	for (int i = 0; i < count; i++) {
		auto &ni = networks[i];
		if (ni.rsn_ie != nullptr)
			IOFree(ni.rsn_ie, ni.ie_len);
	}
	if (networks && count)
		IOFree(networks, count * sizeof(NetworkInformation));
	
	OSObject::free();
}

ScanResult* ScanResult::scanResult() {
	ScanResult *result = new ScanResult;
	if (result == nullptr)
		return nullptr;
	if (!result->init()) {
		result->free();
		return nullptr;
	}
	return result;
}

OSDefineMetaClassAndAbstractStructors(Black80211Device, IOService)

extern IOWorkLoop *_fWorkloop;
extern IOCommandGate *_fCommandGate;

void itlwm::setController(IOEthernetController* io80211controller) {
	struct ieee80211com *ic = &com.sc_ic;
	fController = io80211controller;
	
	_fWorkloop = fController->getWorkLoop();
	if (!getWorkLoop()) {
		XYLog("No workloop\n");
		releaseAll();
		return;
	}

	_fCommandGate = IOCommandGate::commandGate(this, (IOCommandGate::Action)tsleepHandler);
    if (_fCommandGate == 0) {
        XYLog("No command gate!!\n");
        releaseAll();
        return;
    }
    _fWorkloop->addEventSource(_fCommandGate);

	pci.workloop = _fWorkloop;
    pci.pa_tag = pciNub;
	
    if (!iwm_attach(&com, &pci)) {
        releaseAll();
        return;
    }

	ic->ic_des_esslen = 0;
	ic->ic_flags |= IEEE80211_F_AUTO_JOIN; // Makes it not join anything when ic_des_esslen is 0

    fWatchdogWorkLoop = IOWorkLoop::workLoop();
    if (fWatchdogWorkLoop == NULL) {
        releaseAll();
        return;
    }
    watchdogTimer = IOTimerEventSource::timerEventSource(this, OSMemberFunctionCast(IOTimerEventSource::Action, this, &itlwm::watchdogAction));
    if (!watchdogTimer) {
        XYLog("init watchdog fail\n");
        releaseAll();
        return;
    }
    fWatchdogWorkLoop->addEventSource(watchdogTimer);
}

void itlwm::setInterface(IOEthernetInterface* interface) {
	struct ieee80211com *ic = &com.sc_ic;
	fNetIf = interface;

    auto nd = interface->getParameter(kIONetworkStatsKey);
    if (!nd || !(fpNetStats = (IONetworkStats *)nd->getBuffer())) {
        XYLog("network statistics buffer unavailable?\n");
    }
	bzero(ic->ic_rsn_ie_override, 257);
	
	ic->ic_if.netStat = fpNetStats;

	interface->retain();
	ic->ic_if.iface = interface;
}

enum apple80211_authtype_lower
{
    APPLE80211_AUTHTYPE_OPEN        = 1,    // open
    APPLE80211_AUTHTYPE_SHARED      = 2,    // shared key
    APPLE80211_AUTHTYPE_CISCO       = 3,    // cisco net eap
};

enum apple80211_authtype_upper
{
    APPLE80211_AUTHTYPE_NONE         = 0,         //    No upper auth
    APPLE80211_AUTHTYPE_WPA          = 1 << 0,    //    WPA
    APPLE80211_AUTHTYPE_WPA_PSK      = 1 << 1,    //    WPA PSK
    APPLE80211_AUTHTYPE_WPA2         = 1 << 2,    //    WPA2
    APPLE80211_AUTHTYPE_WPA2_PSK     = 1 << 3,    //    WPA2 PSK
    APPLE80211_AUTHTYPE_LEAP         = 1 << 4,    //    LEAP
    APPLE80211_AUTHTYPE_8021X        = 1 << 5,    //    802.1x
    APPLE80211_AUTHTYPE_WPS          = 1 << 6,    //    WiFi Protected Setup
	APPLE80211_AUTHTYPE_SHA256_PSK   = 1 << 7,
	APPLE80211_AUTHTYPE_SHA256_8021X = 1 << 8,
	APPLE80211_AUTHTYPE_WPA3_SAE     = 1 << 9
};

void itlwm::associate(uint8_t *ssid, uint32_t ssid_len, const struct ether_addr &bssid, uint32_t authtype_lower, uint32_t authtype_upper, uint8_t *key, uint32_t key_len, int key_index) {
	struct ieee80211com *ic = &com.sc_ic;

	ieee80211_del_ess(ic, nullptr, 0, 1);

	protect_des_ess = true;
    memset(ic->ic_des_essid, 0, IEEE80211_NWID_LEN);
    ic->ic_des_esslen = (int)strnlen((const char*)ssid, IEEE80211_NWID_LEN);
    memcpy(ic->ic_des_essid, ssid, ic->ic_des_esslen);

	ieee80211_join join;
	bzero(&join, sizeof(ieee80211_join));
	
	join.i_len = ic->ic_des_esslen;
	memcpy(join.i_nwid, ic->ic_des_essid, join.i_len);
	
	bool is_zero = true;
	for (int i = 0; i < IEEE80211_ADDR_LEN; i++)
		is_zero &= bssid.octet[i] == 0;
	
	if (!is_zero) {
		IEEE80211_ADDR_COPY(ic->ic_des_bssid, bssid.octet);
		ic->ic_flags |= IEEE80211_F_DESBSSID;
	}
	else {
		memset(ic->ic_des_bssid, 0, IEEE80211_ADDR_LEN);	
		ic->ic_flags &= ~IEEE80211_F_DESBSSID;
	}
	
	ieee80211_wpaparams& wpa = join.i_wpaparams;
	
	if (authtype_upper & 0xf)
		wpa.i_enabled = 1;
	
	if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA_PSK)) {
		wpa.i_protos |= IEEE80211_WPA_PROTO_WPA1;		
	}
	if (authtype_upper & (APPLE80211_AUTHTYPE_WPA2 | APPLE80211_AUTHTYPE_WPA2_PSK)) {
		wpa.i_protos |= IEEE80211_WPA_PROTO_WPA2;		
	}
	
	if (authtype_upper & (APPLE80211_AUTHTYPE_WPA_PSK | APPLE80211_AUTHTYPE_WPA2_PSK)) {
		wpa.i_akms |= IEEE80211_WPA_AKM_PSK | IEEE80211_WPA_AKM_SHA256_PSK;		
		ieee80211_wpapsk& psk = join.i_wpapsk;
		psk.i_enabled = 1;
		memcpy(psk.i_psk, key, sizeof(psk.i_psk));
		join.i_flags = IEEE80211_JOIN_WPA | IEEE80211_JOIN_WPAPSK;
	}
	if (authtype_upper & (APPLE80211_AUTHTYPE_WPA | APPLE80211_AUTHTYPE_WPA2)) {
		wpa.i_akms |= IEEE80211_WPA_AKM_8021X | IEEE80211_WPA_AKM_SHA256_8021X;				
		join.i_flags = IEEE80211_JOIN_WPA | IEEE80211_JOIN_8021X;
	}
	
	if (authtype_lower == APPLE80211_AUTHTYPE_SHARED) {
		XYLog("shared key authentication is not supported!\n");
		return;
	}
	
	if (authtype_upper == APPLE80211_AUTHTYPE_NONE && authtype_lower == APPLE80211_AUTHTYPE_OPEN) { // Open or WEP Open System
		ieee80211_nwkey& nwkey = join.i_nwkey;
		if (key_len > 0) {
			nwkey.i_wepon = IEEE80211_NWKEY_WEP;
			nwkey.i_defkid = key_index + 1;
			nwkey.i_key[key_index].i_keylen = (int)key_len;
			nwkey.i_key[key_index].i_keydat = (uint8_t*)IOMalloc(key_len); // TODO: check for null!
			memcpy(nwkey.i_key[key_index].i_keydat, key, key_len);
		}
		else
			nwkey.i_wepon = IEEE80211_NWKEY_OPEN;
		join.i_flags |= IEEE80211_JOIN_NWKEY;
	}
	
	ieee80211_add_ess(ic, &join);
    ic->ic_flags &= ~IEEE80211_F_AUTO_JOIN;
	
	ieee80211_switch_ess(ic);
}

void itlwm::enable() {
	enable(fNetIf);
}

void itlwm::disable() {
	disable(fNetIf);
}

void itlwm::getRSNIE(uint16_t &ie_len, uint8_t ie_buf[257]) {
	struct ieee80211com *ic = &com.sc_ic;
	struct ieee80211_node	* bss = com.sc_ic.ic_bss;
	if (ic->ic_state < IEEE80211_S_AUTH || bss == nullptr || bss->ni_rsnie == nullptr) {
		ie_len = 0;
		bzero(ie_buf, 257);
	}
	else if (ic->ic_rsn_ie_override[1] > 0) {
		ie_len = 2 + ic->ic_rsn_ie_override[1];
		memcpy(ie_buf, ic->ic_rsn_ie_override, ie_len);
	}
	else {
		ie_len = 2 + bss->ni_rsnie[1];
		memcpy(ie_buf, bss->ni_rsnie, ie_len);
	}
}

void itlwm::setRSN_IE(const u_int8_t *ie) {
	struct ieee80211com *ic = &com.sc_ic;
	memcpy(ic->ic_rsn_ie_override, ie, 257);
	if (ic->ic_state == IEEE80211_S_RUN && ic->ic_bss != nullptr)
		ieee80211_save_ie(ie, &ic->ic_bss->ni_rsnie);
}

void itlwm::getAP_IE_LIST(uint32_t &ie_list_len, uint8_t *ie_buf) {
	struct ieee80211com *ic = &com.sc_ic;
	struct ieee80211_node	* bss = com.sc_ic.ic_bss;
	if (ic->ic_state < IEEE80211_S_AUTH || bss == nullptr || bss->ni_ie_list == nullptr || bss->ni_ie_list_len > ie_list_len) {
		bzero(ie_buf, ie_list_len);
		ie_list_len = 0;
	}
	else {
		ie_list_len = bss->ni_ie_list_len;
		memcpy(ie_buf, bss->ni_ie_list, ie_list_len);
	}
	XYLog("%s: len %d, state %d, bss %d, ie_list %d, ie_list_len %d\n", __FUNCTION__, ie_list_len, ic->ic_state, bss && true, bss && bss->ni_ie_list, bss ? bss->ni_ie_list_len : 0);
}

void itlwm::setPMKSA(const u_int8_t *key, size_t key_len) {
	struct ieee80211com *ic = &com.sc_ic;
	struct ieee80211_node	* ni = com.sc_ic.ic_bss;

	memcpy(ni->ni_pmk, key, key_len);
    ni->ni_flags |= IEEE80211_NODE_PMK;
	XYLog("%s: Not implemented\n", __FUNCTION__);
}

void itlwm::setPTK(const u_int8_t *key, size_t key_len) {
	struct ieee80211com *ic = &com.sc_ic;
	struct ieee80211_node	* ni = com.sc_ic.ic_bss;
	struct ieee80211_key *k;
	int keylen;
	
	ni->ni_rsn_supp_state = RNSA_SUPP_PTKDONE;
	
	if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP/* &&
		(ni->ni_flags & IEEE80211_NODE_RSN_NEW_PTK)*/) {
		u_int64_t prsc;
		
		/* check that key length matches that of pairwise cipher */
		keylen = ieee80211_cipher_keylen(ni->ni_rsncipher);
		if (key_len != keylen) {
			XYLog("itlwm: PTK length mismatch. expected %d, got %zu\n", keylen, key_len);
			return;
		}
		prsc = /*(gtk == NULL) ? LE_READ_6(key->rsc) :*/ 0;
		
		/* map PTK to 802.11 key */
		k = &ni->ni_pairwise_key;
		memset(k, 0, sizeof(*k));
		k->k_cipher = ni->ni_rsncipher;
		k->k_rsc[0] = prsc;
		k->k_len = keylen;
		memcpy(k->k_key, key, k->k_len);
		/* install the PTK */
		if ((*ic->ic_set_key)(ic, ni, k) != 0) {
			XYLog("setting PTK failed\n");
			return;
		}
		else {
			XYLog("itlwm: set PTK successfully\n");
		}
		ni->ni_flags &= ~IEEE80211_NODE_RSN_NEW_PTK;
		ni->ni_flags &= ~IEEE80211_NODE_TXRXPROT;
		ni->ni_flags |= IEEE80211_NODE_RXPROT;
	} else if (ni->ni_rsncipher != IEEE80211_CIPHER_USEGROUP)
		XYLog("%s: unexpected pairwise key update received from %s\n",
			  ic->ic_if.if_xname, ether_sprintf(ni->ni_macaddr));
	
}

#define LE_READ_6(p)						\
((u_int64_t)(p)[5] << 40 | (u_int64_t)(p)[4] << 32 |	\
 (u_int64_t)(p)[3] << 24 | (u_int64_t)(p)[2] << 16 |	\
 (u_int64_t)(p)[1] <<  8 | (u_int64_t)(p)[0])

void itlwm::setGTK(const u_int8_t *gtk, size_t key_len, u_int8_t kid, u_int8_t *rsc) {
	struct ieee80211com *ic = &com.sc_ic;
	struct ieee80211_node	* ni = com.sc_ic.ic_bss;
	struct ieee80211_key *k;
	int keylen;
	
	if (gtk != NULL) {
		/* check that key length matches that of group cipher */
		keylen = ieee80211_cipher_keylen(ni->ni_rsngroupcipher);
		if (key_len != keylen) {
			XYLog("itlwm: GTK length mismatch. expected %d, got %zu\n", keylen, key_len);
			return;
		}
		/* map GTK to 802.11 key */
		k = &ic->ic_nw_keys[kid];
		memset(k, 0, sizeof(*k));
		k->k_id = kid;    /* 0-3 */
		k->k_cipher = ni->ni_rsngroupcipher;
		k->k_flags = IEEE80211_KEY_GROUP;
		//if (gtk[6] & (1 << 2))
		//	k->k_flags |= IEEE80211_KEY_TX;
		k->k_rsc[0] = LE_READ_6(rsc);
		k->k_len = keylen;
		memcpy(k->k_key, gtk, k->k_len);
		/* install the GTK */
		if ((*ic->ic_set_key)(ic, ni, k) != 0) {
			XYLog("setting GTK failed\n");
			return;
		}
		else {
			XYLog("itlwm: set PTK successfully\n");
		}
	}
	
	if (true) {
		ni->ni_flags |= IEEE80211_NODE_TXRXPROT;
#ifndef IEEE80211_STA_ONLY
		if (ic->ic_opmode != IEEE80211_M_IBSS ||
			++ni->ni_key_count == 2)
#endif
		{
			XYLog("marking port %s valid\n",
					 ether_sprintf(ni->ni_macaddr));
			ni->ni_port_valid = 1;
			ieee80211_set_link_state(ic, LINK_STATE_UP);
			ni->ni_assoc_fail = 0;
			if (ic->ic_opmode == IEEE80211_M_STA)
				ic->ic_rsngroupcipher = ni->ni_rsngroupcipher;
		}
	}
}

int itlwm::getRSSI() {
    ieee80211_node *bss = com.sc_ic.ic_bss;
    return -(bss->ni_rssi);
}

int itlwm::getNoise() {
	return com.sc_noise;
}

ScanResult* itlwm::getScanResult() {
	fInteropScanResult->retain();
	return fInteropScanResult;
}

void itlwm::disassociate() {
	struct ieee80211com *ic = &com.sc_ic;
	protect_des_ess = false;
	ieee80211_set_link_state(ic, LINK_STATE_DOWN);
	ieee80211_del_ess(ic, nullptr, 0, 1);
	ieee80211_deselect_ess(ic);
	ic->ic_rsn_ie_override[1] = 0;
	ic->ic_flags |= IEEE80211_F_AUTO_JOIN; // prevent from joining non-requested open networks
	ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
	//ic->ic_xflags |= IEEE80211_F_EXTERNAL_MGMT;
}

IOReturn itlwm::bgscan(uint8_t* channels, uint32_t length, const char* ssid, uint32_t ssid_len) {
	struct ieee80211com *ic = &com.sc_ic;
	if (!com.sc_init_complete) {
		return kIOReturnError;
	}
	IOLog("Entered background scanning block\n");
	if (ic->ic_state == IEEE80211_S_RUN) {
		if (length == 0) {
			// Scan all channels
			ic->ic_bgscan_all_channels = true;
		}
		else {
			ic->ic_bgscan_all_channels = false;
			u_char ic_chan_scan_target[howmany(IEEE80211_CHAN_MAX,NBBY)];
			bzero(ic_chan_scan_target, sizeof(ic_chan_scan_target));
			setbit(ic_chan_scan_target, channels[ieee80211_chan2ieee(ic, ic->ic_bss->ni_chan)]);
			for (int i = 0; i < length; i++)
				setbit(ic_chan_scan_target, channels[i]);
			static_assert(sizeof(ic->ic_chan_scan_target) == sizeof(ic_chan_scan_target), "arrays should have equal size");
			memcpy(ic->ic_chan_scan_target, ic_chan_scan_target, sizeof(ic_chan_scan_target)); // don't bzero the original array if the scan is in progress
		}

		if (!timeout_pending(&ic->ic_bgscan_timeout) &&
			(ic->ic_flags & IEEE80211_F_BGSCAN) == 0) {
			timeout_add_msec(&ic->ic_bgscan_timeout, 1);
			IOLog("Will begin background scan in 1 ms\n");
		}
		else {
			IOLog("Will not begin background scan. Scan pending: %d, already scanning: %d\n", timeout_pending(&ic->ic_bgscan_timeout), !!(ic->ic_flags & IEEE80211_F_BGSCAN));
		}
	}
	else {
		IOLog("Will begin scan\n");
		if (!protect_des_ess) {
			memcpy(ic->ic_des_essid, ssid, ssid_len);
			ic->ic_des_esslen = ssid_len;
		}
		ieee80211_reset_scan(&ic->ic_if);
		//ieee80211_begin_scan(&ic->ic_if);
	}
	return kIOReturnSuccess;
}

bool itlwm::isScanning() {
	struct ieee80211com *ic = &com.sc_ic;
	return ic->ic_state == IEEE80211_S_SCAN || ic->ic_flags & IEEE80211_F_BGSCAN;
}

void itlwm::getESSID(uint8_t essid[32], uint32_t* len) {
	struct ieee80211com *ic = &com.sc_ic;
	switch (ic->ic_state) {
	case IEEE80211_S_INIT:
	case IEEE80211_S_SCAN:
		*len = ic->ic_des_esslen;
		memcpy(essid, ic->ic_des_essid, *len);
		break;
	default:
		*len = ic->ic_bss->ni_esslen;
		memcpy(essid, ic->ic_bss->ni_essid, *len);
		break;
	}
}

void itlwm::getBSSID(u_int8_t *bssid) {
	struct ieee80211com *ic = &com.sc_ic;
	switch (ic->ic_state) {
	case IEEE80211_S_INIT:
	case IEEE80211_S_SCAN:
#ifndef IEEE80211_STA_ONLY
		if (ic->ic_opmode == IEEE80211_M_HOSTAP)
			IEEE80211_ADDR_COPY(bssid, ic->ic_myaddr);
		else
#endif
		if (ic->ic_flags & IEEE80211_F_DESBSSID)
			IEEE80211_ADDR_COPY(bssid,	ic->ic_des_bssid);
		else
			memset(bssid, 0, IEEE80211_ADDR_LEN);
		break;
	default:
		IEEE80211_ADDR_COPY(bssid,	ic->ic_bss->ni_bssid);
		break;
	}
}

int itlwm::getChannel() {
	struct ieee80211com *ic = &com.sc_ic;
	struct ieee80211_channel *chan;
	switch (ic->ic_state) {
	case IEEE80211_S_INIT:
	case IEEE80211_S_SCAN:
		if (ic->ic_opmode == IEEE80211_M_STA)
			chan = ic->ic_des_chan;
		else
			chan = ic->ic_ibss_chan;
		break;
	default:
		chan = ic->ic_bss->ni_chan;
		break;
	}
	return ieee80211_chan2ieee(ic, chan);
}

int itlwm::getRate() {
	struct ieee80211com *ic = &com.sc_ic;
	return iwm_rates[ieee80211_get_rate(ic)].rate;
}

int itlwm::getMCS() {
	struct ieee80211com *ic = &com.sc_ic;
	if (ic->ic_state == IEEE80211_S_RUN)
		return ic->ic_bss->ni_txmcs;
	return 0;
}

int itlwm::getState() {
	struct ieee80211com *ic = &com.sc_ic;
	return ic->ic_state;
}

enum apple80211_channel_flag
{
    APPLE80211_C_FLAG_NONE        = 0x0,        // no flags
    APPLE80211_C_FLAG_10MHZ        = 0x1,        // 10 MHz wide
    APPLE80211_C_FLAG_20MHZ        = 0x2,        // 20 MHz wide
    APPLE80211_C_FLAG_40MHZ        = 0x4,        // 40 MHz wide
    APPLE80211_C_FLAG_2GHZ        = 0x8,        // 2.4 GHz
    APPLE80211_C_FLAG_5GHZ        = 0x10,        // 5 GHz
    APPLE80211_C_FLAG_IBSS        = 0x20,        // IBSS supported
    APPLE80211_C_FLAG_HOST_AP    = 0x40,        // HOST AP mode supported
    APPLE80211_C_FLAG_ACTIVE    = 0x80,        // active scanning supported
    APPLE80211_C_FLAG_DFS        = 0x100,    // DFS required
    APPLE80211_C_FLAG_EXT_ABV    = 0x200,    // If 40 Mhz, extension channel above.
    // If this flag is not set, then the
    // extension channel is below.
};

void itlwm::getSupportedChannels(uint32_t &channels_count, struct channel_desc channel_desc[64]) {
	struct ieee80211com *ic = &com.sc_ic;
	channels_count = 0;
	for (int i = 0; i < IEEE80211_CHAN_MAX; i++) {
		auto *chan = &ic->ic_channels[i];
		if (chan->ic_flags) {
			auto &chdesc = channel_desc[channels_count];
			chdesc.channel_num = i;
			chdesc.channel_flags = APPLE80211_C_FLAG_NONE;
			if (chan->ic_flags & IEEE80211_CHAN_2GHZ)
				chdesc.channel_flags |= APPLE80211_C_FLAG_2GHZ | APPLE80211_C_FLAG_20MHZ;
			if (chan->ic_flags & IEEE80211_CHAN_5GHZ)
				chdesc.channel_flags |= APPLE80211_C_FLAG_5GHZ | APPLE80211_C_FLAG_40MHZ;
			if (!(chan->ic_flags & IEEE80211_CHAN_PASSIVE))
				chdesc.channel_flags |= APPLE80211_C_FLAG_ACTIVE;

			channels_count++;
			if (channels_count == 64)
				break;
		}
	}
}

IOReturn itlwm::getMACAddress(IOEthernetAddress* address) {
	if (IEEE80211_ADDR_EQ(etheranyaddr, com.sc_ic.ic_myaddr)) {
        return kIOReturnError;
    } else {
        IEEE80211_ADDR_COPY(address, com.sc_ic.ic_myaddr);
        return kIOReturnSuccess;
    }
}

void itlwm::getFirmwareVersion(char version[256], uint16_t &version_len) {
	strncpy(version, com.sc_fwver, MIN(256, sizeof(com.sc_fwver)));
	version_len = strnlen(com.sc_fwver, sizeof(com.sc_fwver));
}

enum apple80211_phymode {
    APPLE80211_MODE_UNKNOWN            = 0,
    APPLE80211_MODE_AUTO               = 0x1,        // autoselect
    APPLE80211_MODE_11A                = 0x2,        // 5GHz, OFDM
    APPLE80211_MODE_11B                = 0x4,        // 2GHz, CCK
    APPLE80211_MODE_11G                = 0x8,        // 2GHz, OFDM
    APPLE80211_MODE_11N                = 0x10,        // 2GHz/5GHz, OFDM
    APPLE80211_MODE_TURBO_A            = 0x20,        // 5GHz, OFDM, 2x clock
    APPLE80211_MODE_TURBO_G            = 0x40,        // 2GHz, OFDM, 2x clock
	APPLE80211_MODE_11AC 			   = 0x80,
};

uint32_t itlwm::getPHYMode() {
	switch (com.sc_ic.ic_curmode) {
		case IEEE80211_MODE_11A:
			return APPLE80211_MODE_11A;
		case IEEE80211_MODE_11B:
			return APPLE80211_MODE_11B;
		case IEEE80211_MODE_11G:
			return APPLE80211_MODE_11G;
		case IEEE80211_MODE_11N:
			return APPLE80211_MODE_11N;
		case IEEE80211_MODE_11AC:
			return APPLE80211_MODE_11AC;
		case IEEE80211_MODE_AUTO:
			return APPLE80211_MODE_AUTO;
		default:
			return APPLE80211_MODE_UNKNOWN;
	}
}

uint32_t itlwm::getSupportedPHYModes() {
	uint32_t modes = 0;
	if (com.sc_ic.ic_modecaps & IEEE80211_MODE_11A)
		modes |= APPLE80211_MODE_11A;
	if (com.sc_ic.ic_modecaps & IEEE80211_MODE_11B)
		modes |= APPLE80211_MODE_11B;
	if (com.sc_ic.ic_modecaps & IEEE80211_MODE_11G)
		modes |= APPLE80211_MODE_11G;
	if (com.sc_ic.ic_modecaps & IEEE80211_MODE_11N)
		modes |= APPLE80211_MODE_11N;
	if (com.sc_ic.ic_modecaps & IEEE80211_MODE_11AC)
		modes |= APPLE80211_MODE_11AC;
	if (com.sc_ic.ic_modecaps & IEEE80211_MODE_AUTO)
		modes |= APPLE80211_MODE_AUTO;
	return modes;
}

void itlwm::getCountryCode(char countryCode[3]) {
	memcpy(countryCode, com.sc_fw_mcc, 3);
}

enum apple80211_opmode {
    APPLE80211_M_NONE        = 0x0,
    APPLE80211_M_STA        = 0x1,        // infrastructure station
    APPLE80211_M_IBSS        = 0x2,        // IBSS (adhoc) station
    APPLE80211_M_AHDEMO        = 0x4,        // Old lucent compatible adhoc demo
    APPLE80211_M_HOSTAP        = 0x8,        // Software Access Point
    APPLE80211_M_MONITOR    = 0x10        // Monitor mode
};

uint32_t itlwm::getOpMode() {
	switch (com.sc_ic.ic_opmode) {
		case IEEE80211_M_STA:
			return APPLE80211_M_STA;
#ifndef IEEE80211_STA_ONLY
		case IEEE80211_M_IBSS:
			return APPLE80211_M_IBSS;
		case IEEE80211_M_AHDEMO:
			return APPLE80211_M_AHDEMO;
		case IEEE80211_M_HOSTAP:
			return APPLE80211_M_HOSTAP;
#endif
		case IEEE80211_M_MONITOR:
			return APPLE80211_M_MONITOR;
		default:
			return APPLE80211_M_NONE;			
	}
}


UInt32 itlwm::outputPacket(mbuf_t m, void *param)
{
	//    XYLog("%s\n", __FUNCTION__);
    ifnet *ifp = &com.sc_ic.ic_ac.ac_if;

    if (com.sc_ic.ic_state < IEEE80211_S_AUTH || ifp == NULL || ifp->if_snd == NULL) {
        fController->freePacket(m);
        return kIOReturnOutputDropped;
    }
    if (m == NULL) {
        XYLog("%s m==NULL!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        return kIOReturnOutputDropped;
    }
    if (!(mbuf_flags(m) & MBUF_PKTHDR) ){
        XYLog("%s pkthdr is NULL!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        return kIOReturnOutputDropped;
    }
    if (mbuf_type(m) == MBUF_TYPE_FREE) {
        XYLog("%s mbuf is FREE!!\n", __FUNCTION__);
        ifp->netStat->outputErrors++;
        return kIOReturnOutputDropped;
    }
	if (ifp->if_snd->lockEnqueue(m)) {
		(*ifp->if_start)(ifp);
	}
	else {
		XYLog("Packet dropped\n");
		return kIOReturnOutputDropped;
	}

    return kIOReturnOutputSuccess;
}

#endif
