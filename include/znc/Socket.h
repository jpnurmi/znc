/*
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ZNC_SOCKET_H
#define ZNC_SOCKET_H

#include <znc/zncconfig.h>
#include <znc/Csocket.h>
#include <znc/Threads.h>

class CModule;

class CZNCSock : public Csock {
public:
	CZNCSock(int timeout = 60);
	CZNCSock(const CString& sHost, u_short port, int timeout = 60);
	~CZNCSock() {}

	int ConvertAddress(const struct sockaddr_storage * pAddr, socklen_t iAddrLen, CS_STRING & sIP, u_short * piPort) const override;
#ifdef HAVE_LIBSSL
	int VerifyPeerCertificate(int iPreVerify, X509_STORE_CTX * pStoreCTX) override;
	void SSLHandShakeFinished() override;
#endif
	void SetHostToVerifySSL(const CString& sHost) { m_HostToVerifySSL = sHost; }
	CString GetSSLPeerFingerprint() const;
	void SetSSLTrustedPeerFingerprints(const SCString& ssFPs) { m_ssTrustedFingerprints = ssFPs; }

#ifndef HAVE_ICU
	// Don't fail to compile when ICU is not enabled
	void SetEncoding(const CString&) {}
#endif
	virtual CString GetRemoteIP() const { return Csock::GetRemoteIP(); }

	/// @brief For client<->ZNC, and ZNC<->server IRC sockets
	bool GetAllowIRCControlCodes() const { return m_bAllowIRCControlCodes; }
	void SetAllowIRCControlCodes(bool bAllow) { m_bAllowIRCControlCodes = bAllow; }

#ifdef HAVE_ICU
	/**
	 * @brief Allow IRC control characters to appear even if protocol encoding explicitly disallows them.
	 *
	 * E.g. ISO-2022-JP disallows 0x0F, which in IRC means "reset format",
	 * so by default it gets replaced with U+FFFD ("replacement character").
	 * https://code.google.com/p/chromium/issues/detail?id=277062#c3
	 *
	 * In case if protocol encoding uses these code points for something else, the encoding takes preference,
	 * and they are not IRC control characters anymore.
	 */
	void IcuExtToUCallback(
		UConverterToUnicodeArgs* toArgs,
		const char* codeUnits,
		int32_t length,
		UConverterCallbackReason reason,
		UErrorCode* err) override;
	void IcuExtFromUCallback(
		UConverterFromUnicodeArgs* fromArgs,
		const UChar* codeUnits,
		int32_t length,
		UChar32 codePoint,
		UConverterCallbackReason reason,
		UErrorCode* err) override;
#endif

protected:
	// All existing errno codes seem to be in range 1-300
	enum {
		errnoBadSSLCert = 12569,
	};

private:
	bool m_bAllowIRCControlCodes;
	CString m_HostToVerifySSL;
	SCString m_ssTrustedFingerprints;
	SCString m_ssCertVerificationErrors;
};

enum EAddrType {
	ADDR_IPV4ONLY,
	ADDR_IPV6ONLY,
	ADDR_ALL
};

/**
 * @class CSocket
 * @brief Base Csock implementation to be used by modules
 *
 * By all means, this class should be used as a base for sockets originating from modules. It handles removing instances of itself
 * from the module as it unloads, and simplifies use in general.
 * - EnableReadLine is default to true in this class
 * - MaxBuffer for readline is set to 10240, in the event this is reached the socket is closed (@see ReachedMaxBuffer)
 */
class CSocket : public CZNCSock {
public:
	/**
	 * @brief ctor
	 * @param pModule the module this sock instance is associated to
	 */
	CSocket(CModule* pModule);
	/**
	 * @brief ctor
	 * @param pModule the module this sock instance is associated to
	 * @param sHostname the hostname being connected to
	 * @param uPort the port being connected to
	 * @param iTimeout the timeout period for this specific sock
	 */
	CSocket(CModule* pModule, const CString& sHostname, unsigned short uPort, int iTimeout = 60);
	virtual ~CSocket();

	CSocket(const CSocket&) = delete;
	CSocket& operator=(const CSocket&) = delete;

	using Csock::Connect;
	using Csock::Listen;

	//! This defaults to closing the socket, feel free to override
	void ReachedMaxBuffer() override;
	void SockError(int iErrno, const CString& sDescription) override;

	//! This limits the global connections from this IP to defeat DoS attacks, feel free to override. The ACL used is provided by the main interface @see CZNC::AllowConnectionFrom
	bool ConnectionFrom(const CString& sHost, unsigned short uPort) override;

	//! Ease of use Connect, assigns to the manager and is subsequently tracked
	bool Connect(const CString& sHostname, unsigned short uPort, bool bSSL = false, unsigned int uTimeout = 60);
	//! Ease of use Listen, assigned to the manager and is subsequently tracked
	bool Listen(unsigned short uPort, bool bSSL, unsigned int uTimeout = 0);

	// Getters
	CModule* GetModule() const;
	// !Getters

private:
	CModule*  m_pModule; //!< pointer to the module that this sock instance belongs to
};

#endif /* ZNC_SOCKET_H */
