package de.thoffbauer.signal4j.listener;

import java.util.List;

import org.whispersystems.signalservice.api.messages.multidevice.BlockedListMessage;
import org.whispersystems.signalservice.api.messages.multidevice.DeviceContact;
import org.whispersystems.signalservice.api.messages.multidevice.DeviceGroup;
import org.whispersystems.signalservice.api.messages.multidevice.ReadMessage;
import org.whispersystems.signalservice.api.messages.multidevice.SentTranscriptMessage;

public interface SyncMessageListener {

	void onContactsSync(List<DeviceContact> contactList);
	void onGroupsSync(List<DeviceGroup> groupList);
	void onTranscriptSync(SentTranscriptMessage transcript);
	void onReadSync(List<ReadMessage> readList);
	void onBlockedSync(List<BlockedListMessage> blockedList);

}
