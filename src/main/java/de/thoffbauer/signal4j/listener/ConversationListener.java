package de.thoffbauer.signal4j.listener;

import java.util.List;

import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.signalservice.api.messages.multidevice.ReadMessage;

import de.thoffbauer.signal4j.store.User;
import de.thoffbauer.signal4j.store.Group;

public interface ConversationListener {
	
	/**
	 * Called every time we receive a message or another device of us sends a message
	 * @param sender
	 * @param message
	 * @param group null if not in a group
	 */
	void onMessage(User sender, SignalServiceDataMessage message, Group group);
	
	/**
	 * Called if the metadata of a contact changes.
	 * @param contact the new contact
	 */
	void onContactUpdate(User contact);
	
	/**
	 * Called if the metadata of a group changes.
	 * @param sender who changed the group
	 * @param group the new group
	 */
	void onGroupUpdate(User sender, Group group);
	
	/**
	 * Send by another device of us once messages are read. Each {@code ReadMessage} contains
	 * the timestamp and the sender of a read message.
	 * @param readList
	 */
	void onReadUpdate(List<ReadMessage> readList);

}
