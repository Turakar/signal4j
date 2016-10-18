package de.thoffbauer.signal4j.listener;

import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;

public interface DataMessageListener {
	
	void onMessageReceived(SignalServiceAddress sender, SignalServiceDataMessage message);

}
