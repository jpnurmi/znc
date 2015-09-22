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

#include <znc/Chan.h>
#include <znc/IRCNetwork.h>

using std::vector;

class CBuffExtras : public CModule {
public:
	MODCONSTRUCTOR(CBuffExtras) {}

	virtual ~CBuffExtras() {}

	void AddBuffer(CChan& Channel, const CMessage& Message, const CString& sText) {
		// If they have AutoClearChanBuffer enabled, only add messages if no client is connected
		if (Channel.AutoClearChanBuffer() && GetNetwork()->IsUserOnline())
			return;

		CNick Nick(GetModNick() + "!" + GetModName() + "@znc.in");
		CMessage Format(Nick, "PRIVMSG", {_NAMEDFMT(Channel.GetName()), "{text}"}, Message.GetTags());
		Format.SetTime(Message.GetTime());
		Channel.AddBuffer(Format, sText);
	}

	void OnModeMessage(CModeMessage& Message) override {
		CChan* pChan = Message.GetChan();
		if (pChan) {
			const CNick& Nick = Message.GetNick();
			const CString sModes = Message.GetModes();
			AddBuffer(*pChan, Message, Nick.GetNickMask() + " set mode: " + sModes);
		}
	}

	void OnKickMessage(CKickMessage& Message) override {
		const CNick& OpNick = Message.GetNick();
		const CString sKickedNick = Message.GetKickedNick();
		CChan& Channel = *Message.GetChan();
		const CString sMessage = Message.GetReason();
		AddBuffer(Channel, Message, OpNick.GetNickMask() + " kicked " + sKickedNick + " Reason: [" + sMessage + "]");
	}

	void OnQuitMessage(CQuitMessage& Message, const vector<CChan*>& vChans) override {
		const CNick& Nick = Message.GetNick();
		const CString sMessage = Message.GetReason();
		CString sMsg = Nick.GetNickMask() + " quit with message: [" + sMessage + "]";
		for (CChan* pChan : vChans) {
			AddBuffer(*pChan, Message, sMsg);
		}
	}

	void OnJoinMessage(CJoinMessage& Message) override {
		const CNick& Nick = Message.GetNick();
		CChan& Channel = *Message.GetChan();
		AddBuffer(Channel, Message, Nick.GetNickMask() + " joined");
	}

	void OnPartMessage(CPartMessage& Message) override {
		const CNick& Nick = Message.GetNick();
		CChan& Channel = *Message.GetChan();
		const CString sMessage = Message.GetReason();
		AddBuffer(Channel, Message, Nick.GetNickMask() + " parted with message: [" + sMessage + "]");
	}

	void OnNickMessage(CNickMessage& Message, const vector<CChan*>& vChans) override {
		const CNick& OldNick = Message.GetNick();
		const CString sNewNick = Message.GetNewNick();
		CString sMsg = OldNick.GetNickMask() + " is now known as " + sNewNick;
		for (CChan* pChan : vChans) {
			AddBuffer(*pChan, Message, sMsg);
		}
	}

	EModRet OnTopicMessage(CTopicMessage& Message) override {
		const CNick& Nick = Message.GetNick();
		CChan& Channel = *Message.GetChan();
		const CString sTopic = Message.GetTopic();
		AddBuffer(Channel, Message, Nick.GetNickMask() + " changed the topic to: " + sTopic);

		return CONTINUE;
	}
};

template<> void TModInfo<CBuffExtras>(CModInfo& Info) {
	Info.SetWikiPage("buffextras");
	Info.AddType(CModInfo::NetworkModule);
}

USERMODULEDEFS(CBuffExtras, "Add joins, parts etc. to the playback buffer")

