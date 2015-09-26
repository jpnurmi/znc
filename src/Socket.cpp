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

#include <znc/Socket.h>
#include <znc/SocketManager.h>
#include <znc/User.h>
#include <znc/IRCNetwork.h>
#include <znc/SSLVerifyHost.h>
#include <znc/znc.h>
#include <signal.h>

#ifdef HAVE_ICU
#include <unicode/ucnv_cb.h>
#endif

#ifdef HAVE_LIBSSL
// Copypasted from https://wiki.mozilla.org/Security/Server_Side_TLS#Intermediate_compatibility_.28default.29 at 22 Dec 2014
CString ZNC_DefaultCipher() {
    return
        "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:"
        "DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:"
        "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:"
        "ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:"
        "DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:"
        "AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA";
}
#endif

CZNCSock::CZNCSock(int timeout) : Csock(timeout), m_HostToVerifySSL(""), m_ssTrustedFingerprints(), m_ssCertVerificationErrors() {
#ifdef HAVE_LIBSSL
	DisableSSLCompression();
	FollowSSLCipherServerPreference();
	DisableSSLProtocols(CZNC::Get().GetDisabledSSLProtocols());
	CString sCipher = CZNC::Get().GetSSLCiphers();
	if (sCipher.empty()) {
		sCipher = ZNC_DefaultCipher();
	}
	SetCipher(sCipher);
#endif
}

CZNCSock::CZNCSock(const CString& sHost, u_short port, int timeout) : Csock(sHost, port, timeout), m_HostToVerifySSL(""), m_ssTrustedFingerprints(), m_ssCertVerificationErrors() {
#ifdef HAVE_LIBSSL
	DisableSSLCompression();
	FollowSSLCipherServerPreference();
	DisableSSLProtocols(CZNC::Get().GetDisabledSSLProtocols());
#endif
}

int CZNCSock::ConvertAddress(const struct sockaddr_storage * pAddr, socklen_t iAddrLen, CS_STRING & sIP, u_short * piPort) const {
	int ret = Csock::ConvertAddress(pAddr, iAddrLen, sIP, piPort);
	if (ret == 0)
		sIP.TrimPrefix("::ffff:");
	return ret;
}

#ifdef HAVE_LIBSSL
int CZNCSock::VerifyPeerCertificate(int iPreVerify, X509_STORE_CTX * pStoreCTX) {
	if (iPreVerify == 0) {
		m_ssCertVerificationErrors.insert(X509_verify_cert_error_string(X509_STORE_CTX_get_error(pStoreCTX)));
	}
	return 1;
}

void CZNCSock::SSLHandShakeFinished() {
	if (GetType() != ETConn::OUTBOUND) {
		return;
	}

	X509* pCert = GetX509();
	if (!pCert) {
		DEBUG(GetSockName() + ": No cert");
		CallSockError(errnoBadSSLCert, "Anonymous SSL cert is not allowed");
		Close();
		return;
	}
	CString sHostVerifyError;
	if (!ZNC_SSLVerifyHost(m_HostToVerifySSL, pCert, sHostVerifyError)) {
		m_ssCertVerificationErrors.insert(sHostVerifyError);
	}
	X509_free(pCert);
	if (m_ssCertVerificationErrors.empty()) {
		DEBUG(GetSockName() + ": Good cert");
		return;
	}
	CString sFP = GetSSLPeerFingerprint();
	if (m_ssTrustedFingerprints.count(sFP) != 0) {
		DEBUG(GetSockName() + ": Cert explicitly trusted by user: " << sFP);
		return;
	}
	DEBUG(GetSockName() + ": Bad cert");
	CString sErrorMsg = "Invalid SSL certificate: ";
	sErrorMsg += CString(", ").Join(begin(m_ssCertVerificationErrors), end(m_ssCertVerificationErrors));
	CallSockError(errnoBadSSLCert, sErrorMsg);
	Close();
}
#endif

CString CZNCSock::GetSSLPeerFingerprint() const {
#ifdef HAVE_LIBSSL
	// Csocket's version returns insecure SHA-1
	// This one is SHA-256
	const EVP_MD* evp = EVP_sha256();
	X509* pCert = GetX509();
	if (!pCert) {
		DEBUG(GetSockName() + ": GetSSLPeerFingerprint: Anonymous cert");
		return "";
	}
	unsigned char buf[256/8];
	unsigned int _32 = 256/8;
	int iSuccess = X509_digest(pCert, evp, buf, &_32);
	X509_free(pCert);
	if (!iSuccess) {
		DEBUG(GetSockName() + ": GetSSLPeerFingerprint: Couldn't find digest");
		return "";
	}
	return CString(reinterpret_cast<const char*>(buf), sizeof buf).Escape_n(CString::EASCII, CString::EHEXCOLON);
#else
	return "";
#endif
}

/////////////////// CSocket ///////////////////
CSocket::CSocket(CModule* pModule) : CZNCSock(), m_pModule(pModule) {
	if (m_pModule) m_pModule->AddSocket(this);
	EnableReadLine();
	SetMaxBufferThreshold(10240);
}

CSocket::CSocket(CModule* pModule, const CString& sHostname, unsigned short uPort, int iTimeout) : CZNCSock(sHostname, uPort, iTimeout), m_pModule(pModule) {
	if (m_pModule) m_pModule->AddSocket(this);
	EnableReadLine();
	SetMaxBufferThreshold(10240);
}

CSocket::~CSocket() {
	CUser *pUser = nullptr;
	CIRCNetwork* pNetwork = nullptr;

	// CWebSock could cause us to have a nullptr pointer here
	if (m_pModule) {
		pUser = m_pModule->GetUser();
		pNetwork = m_pModule->GetNetwork();
		m_pModule->UnlinkSocket(this);
	}

	if (pNetwork && m_pModule && (m_pModule->GetType() == CModInfo::NetworkModule)) {
		pNetwork->AddBytesWritten(GetBytesWritten());
		pNetwork->AddBytesRead(GetBytesRead());
	} else if (pUser && m_pModule && (m_pModule->GetType() == CModInfo::UserModule)) {
		pUser->AddBytesWritten(GetBytesWritten());
		pUser->AddBytesRead(GetBytesRead());
	} else {
		CZNC::Get().AddBytesWritten(GetBytesWritten());
		CZNC::Get().AddBytesRead(GetBytesRead());
	}
}

void CSocket::ReachedMaxBuffer() {
	DEBUG(GetSockName() << " == ReachedMaxBuffer()");
	if (m_pModule) m_pModule->PutModule("Some socket reached its max buffer limit and was closed!");
	Close();
}

void CSocket::SockError(int iErrno, const CString& sDescription) {
	DEBUG(GetSockName() << " == SockError(" << sDescription << ", " << strerror(iErrno) << ")");
	if (iErrno == EMFILE) {
		// We have too many open fds, this can cause a busy loop.
		Close();
	}
}

bool CSocket::ConnectionFrom(const CString& sHost, unsigned short uPort) {
	return CZNC::Get().AllowConnectionFrom(sHost);
}

bool CSocket::Connect(const CString& sHostname, unsigned short uPort, bool bSSL, unsigned int uTimeout) {
	if (!m_pModule) {
		DEBUG("ERROR: CSocket::Connect called on instance without m_pModule handle!");
		return false;
	}

	CUser* pUser = m_pModule->GetUser();
	CString sSockName = "MOD::C::" + m_pModule->GetModName();
	CString sBindHost;

	if (pUser) {
		sSockName += "::" + pUser->GetUserName();
		sBindHost = pUser->GetBindHost();
		CIRCNetwork* pNetwork = m_pModule->GetNetwork();
		if (pNetwork) {
			sSockName += "::" + pNetwork->GetName();
			sBindHost = pNetwork->GetBindHost();
		}
	}

	// Don't overwrite the socket name if one is already set
	if (!GetSockName().empty()) {
		sSockName = GetSockName();
	}

	m_pModule->GetManager()->Connect(sHostname, uPort, sSockName, uTimeout, bSSL, sBindHost, this);
	return true;
}

bool CSocket::Listen(unsigned short uPort, bool bSSL, unsigned int uTimeout) {
	if (!m_pModule) {
		DEBUG("ERROR: CSocket::Listen called on instance without m_pModule handle!");
		return false;
	}

	CUser* pUser = m_pModule->GetUser();
	CString sSockName = "MOD::L::" + m_pModule->GetModName();

	if (pUser) {
		sSockName += "::" + pUser->GetUserName();
	}
	// Don't overwrite the socket name if one is already set
	if (!GetSockName().empty()) {
		sSockName = GetSockName();
	}

	return m_pModule->GetManager()->ListenAll(uPort, sSockName, bSSL, SOMAXCONN, this);
}

CModule* CSocket::GetModule() const { return m_pModule; }
/////////////////// !CSocket ///////////////////

#ifdef HAVE_ICU
void CIRCSocket::IcuExtToUCallback(
		UConverterToUnicodeArgs* toArgs,
		const char* codeUnits,
		int32_t length,
		UConverterCallbackReason reason,
		UErrorCode* err) {
	// From http://www.mirc.com/colors.html
	// The Control+O key combination in mIRC inserts ascii character 15,
	// which turns off all previous attributes, including color, bold, underline, and italics.
	//
	// \x02 bold
	// \x03 mIRC-compatible color
	// \x04 RRGGBB color
	// \x0F normal/reset (turn off bold, colors, etc.)
	// \x12 reverse (weechat)
	// \x16 reverse (mirc, kvirc)
	// \x1D italic
	// \x1F underline
	// Also see http://www.visualirc.net/tech-attrs.php
	//
	// Keep in sync with CUser::AddTimestamp and CIRCSocket::IcuExtFromUCallback
	static const std::set<char> scAllowedChars = {'\x02', '\x03', '\x04', '\x0F', '\x12', '\x16', '\x1D', '\x1F'};
	if (reason == UCNV_ILLEGAL && length == 1 && scAllowedChars.count(*codeUnits)) {
		*err = U_ZERO_ERROR;
		UChar c = *codeUnits;
		ucnv_cbToUWriteUChars(toArgs, &c, 1, 0, err);
		return;
	}
	Csock::IcuExtToUCallback(toArgs, codeUnits, length, reason, err);
}

void CIRCSocket::IcuExtFromUCallback(
		UConverterFromUnicodeArgs* fromArgs,
		const UChar* codeUnits,
		int32_t length,
		UChar32 codePoint,
		UConverterCallbackReason reason,
		UErrorCode* err) {
	// See comment in CIRCSocket::IcuExtToUCallback
	static const std::set<UChar32> scAllowedChars = {0x02, 0x03, 0x04, 0x0F, 0x12, 0x16, 0x1D, 0x1F};
	if (reason == UCNV_ILLEGAL && scAllowedChars.count(codePoint)) {
		*err = U_ZERO_ERROR;
		char c = codePoint;
		ucnv_cbFromUWriteBytes(fromArgs, &c, 1, 0, err);
		return;
	}
	Csock::IcuExtFromUCallback(fromArgs, codeUnits, length, codePoint, reason, err);
}
#endif
