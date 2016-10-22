package de.thoffbauer.signal4j.listener;

import org.whispersystems.signalservice.api.push.SignalServiceAddress;

public interface SecurityExceptionListener {
	
	void onSecurityException(SignalServiceAddress sender, Exception e);

}
