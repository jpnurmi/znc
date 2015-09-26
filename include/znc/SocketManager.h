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

#ifndef ZNC_SOCKETMANAGER_H
#define ZNC_SOCKETMANAGER_H

#include <znc/zncconfig.h>
#include <znc/Socket.h>
#include <znc/ZNCString.h>

class CSockManager : public TSocketManager<CZNCSock> {
public:
	CSockManager();
	virtual ~CSockManager();

	bool ListenHost(u_short iPort, const CString& sSockName, const CString& sBindHost, bool bSSL = false, int iMaxConns = SOMAXCONN, CZNCSock *pcSock = nullptr, u_int iTimeout = 0, EAddrType eAddr = ADDR_ALL);
	bool ListenAll(u_short iPort, const CString& sSockName, bool bSSL = false, int iMaxConns = SOMAXCONN, CZNCSock *pcSock = nullptr, u_int iTimeout = 0, EAddrType eAddr = ADDR_ALL);
	u_short ListenRand(const CString& sSockName, const CString& sBindHost, bool bSSL = false, int iMaxConns = SOMAXCONN, CZNCSock *pcSock = nullptr, u_int iTimeout = 0, EAddrType eAddr = ADDR_ALL);
	u_short ListenAllRand(const CString& sSockName, bool bSSL = false, int iMaxConns = SOMAXCONN, CZNCSock *pcSock = nullptr, u_int iTimeout = 0, EAddrType eAddr = ADDR_ALL);

	void Connect(const CString& sHostname, u_short iPort, const CString& sSockName, int iTimeout = 60, bool bSSL = false, const CString& sBindHost = "", CZNCSock *pcSock = nullptr);
	void FinishConnect(const CString& sHostname, u_short iPort, const CString& sSockName, int iTimeout, bool bSSL, const CString& sBindHost, CZNCSock *pcSock);

	unsigned int GetAnonConnectionCount(const CString &sIP) const;

private:
	class CTDNSMonitorFD;
	friend class CTDNSMonitorFD;
};

#endif /* ZNC_SOCKETMANAGER_H */
