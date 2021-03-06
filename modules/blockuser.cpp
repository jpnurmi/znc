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

#include <znc/Modules.h>
#include <znc/User.h>
#include <znc/IRCNetwork.h>
#include <znc/Socket.h>

using std::vector;

#define DEFAULT_REASON "Your account has been disabled. Contact your administrator."

class CBlockUser : public CModule {
public:
	MODCONSTRUCTOR(CBlockUser) {
		AddHelpCommand();
		AddCommand("List", static_cast<CModCommand::ModCmdFunc>(&CBlockUser::OnListCommand), "", "List blocked users");
		AddCommand("Block", static_cast<CModCommand::ModCmdFunc>(&CBlockUser::OnBlockCommand), "<user> [reason]", "Block a user");
		AddCommand("Unblock", static_cast<CModCommand::ModCmdFunc>(&CBlockUser::OnUnblockCommand), "<user>", "Unblock a user");
	}

	virtual ~CBlockUser() {}

	bool OnLoad(const CString& sArgs, CString& sMessage) override {
		VCString vArgs;
		MCString::iterator it;

		// Load saved settings
		for (it = BeginNV(); it != EndNV(); ++it) {
			// Ignore errors
			Block(it->first, it->second);
		}

		// Parse arguments, each argument is a user name to block
		sArgs.Split(" ", vArgs, false);

		for (const CString& sArg : vArgs) {
			if (!Block(sArg)) {
				sMessage = "Could not block [" + sArg + "]";
				return false;
			}
		}

		return true;
	}

	EModRet OnLoginAttempt(std::shared_ptr<CAuthBase> Auth) override {
		if (IsBlocked(Auth->GetUsername())) {
			CString sReason = GetNV(Auth->GetUsername());
			Auth->RefuseLogin("Blocked: " + (sReason.empty() ? DEFAULT_REASON : sReason));
			return HALT;
		}

		return CONTINUE;
	}

	void OnModCommand(const CString& sCommand) override {
		if (!GetUser()->IsAdmin()) {
			PutModule("Access denied");
		} else {
			HandleCommand(sCommand);
		}
	}

	void OnListCommand(const CString& sCommand) {
		CTable Table;
		MCString::iterator it;

		Table.AddColumn("User");
		Table.AddColumn("Reason");

		for (it = BeginNV(); it != EndNV(); ++it) {
			Table.AddRow();
			Table.SetCell("User", it->first);
			if (it->second.empty()) {
				Table.SetCell("Reason", DEFAULT_REASON + CString(" (default)"));
			} else {
				Table.SetCell("Reason", it->second);
			}
		}

		if (PutModule(Table) == 0)
			PutModule("No users blocked");
	}

	void OnBlockCommand(const CString& sCommand) {
		CString sUser = sCommand.Token(1);
		CString sReason = sCommand.Token(2, true);

		if (sUser.empty()) {
			PutModule("Usage: Block <user> [reason]");
			return;
		}

		if (GetUser()->GetUserName().Equals(sUser)) {
			PutModule("You can't block yourself");
			return;
		}

		if (Block(sUser, sReason))
			PutModule("Blocked [" + sUser + "]");
		else
			PutModule("Could not block [" + sUser + "] (misspelled?)");
	}

	void OnUnblockCommand(const CString& sCommand) {
		CString sUser = sCommand.Token(1, true);

		if (sUser.empty()) {
			PutModule("Usage: Unblock <user>");
			return;
		}

		if (DelNV(sUser))
			PutModule("Unblocked [" + sUser + "]");
		else
			PutModule("This user is not blocked");
	}

	bool OnEmbeddedWebRequest(CWebSock& WebSock, const CString& sPageName, CTemplate& Tmpl) override {
		if (sPageName == "webadmin/user" && WebSock.GetSession()->IsAdmin()) {
			CString sAction = Tmpl["WebadminAction"];
			if (sAction == "display") {
				Tmpl["Blocked"] = CString(IsBlocked(Tmpl["Username"]));
				Tmpl["Reason"] = CString(GetNV(Tmpl["Username"]));
				Tmpl["Self"] = CString(Tmpl["Username"].Equals(WebSock.GetSession()->GetUser()->GetUserName()));
				return true;
			}
			if (sAction == "change" && WebSock.GetParam("embed_blockuser_presented").ToBool()) {
				if (Tmpl["Username"].Equals(WebSock.GetSession()->GetUser()->GetUserName()) &&
						WebSock.GetParam("embed_blockuser_block").ToBool()) {
					WebSock.GetSession()->AddError("You can't block yourself");
				} else if (WebSock.GetParam("embed_blockuser_block").ToBool()) {
					if (!WebSock.GetParam("embed_blockuser_old").ToBool() || WebSock.GetParam("embed_blockuser_reason") != GetNV(Tmpl["Username"])) {
						if (Block(Tmpl["Username"], WebSock.GetParam("embed_blockuser_reason"))) {
							WebSock.GetSession()->AddSuccess("Blocked [" + Tmpl["Username"] + "]");
						} else {
							WebSock.GetSession()->AddError("Couldn't block [" + Tmpl["Username"] + "]");
						}
					}
				} else  if (WebSock.GetParam("embed_blockuser_old").ToBool()){
					if (DelNV(Tmpl["Username"])) {
						WebSock.GetSession()->AddSuccess("Unblocked [" + Tmpl["Username"] + "]");
					} else {
						WebSock.GetSession()->AddError("User [" + Tmpl["Username"] + "is not blocked");
					}
				}
				return true;
			}
		}
		return false;
	}

private:
	bool IsBlocked(const CString& sUser) {
		MCString::iterator it;
		for (it = BeginNV(); it != EndNV(); ++it) {
			if (sUser == it->first) {
				return true;
			}
		}
		return false;
	}

	bool Block(const CString& sUser, const CString& sReason = "") {
		CUser *pUser = CZNC::Get().FindUser(sUser);

		if (!pUser)
			return false;

		// Disconnect all clients
		vector<CClient*> vpClients = pUser->GetAllClients();
		for (CClient* pClient : vpClients) {
			pClient->PutStatusNotice("Blocked: " + (sReason.empty() ? DEFAULT_REASON : sReason));
			pClient->GetSocket()->Close(CZNCSock::CLT_AFTERWRITE);
		}

		// Disconnect all networks from irc
		vector<CIRCNetwork*> vNetworks = pUser->GetNetworks();
		for (CIRCNetwork* pNetwork : vNetworks) {
			pNetwork->SetIRCConnectEnabled(false);
		}

		SetNV(pUser->GetUserName(), sReason);
		return true;
	}


};

template<> void TModInfo<CBlockUser>(CModInfo& Info) {
	Info.SetWikiPage("blockuser");
	Info.SetHasArgs(true);
	Info.SetArgsHelpText("Enter one or more user names. Separate them by spaces.");
}

GLOBALMODULEDEFS(CBlockUser, "Block certain users from logging in.")
