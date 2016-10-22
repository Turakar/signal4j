package de.thoffbauer.signal4j.listener;

import java.util.List;

import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.signalservice.api.messages.multidevice.ReadMessage;

import de.thoffbauer.signal4j.store.User;
import de.thoffbauer.signal4j.store.Group;

public interface ConversationListener {
	
	void onMessage(User sender, SignalServiceDataMessage message, Group group);
	void onContactUpdate(User contact);
	void onGroupUpdate(User sender, Group group);
	void onReadUpdate(List<ReadMessage> readList);

}
