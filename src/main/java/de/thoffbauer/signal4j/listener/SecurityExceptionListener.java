package de.thoffbauer.signal4j.listener;

import de.thoffbauer.signal4j.store.User;

public interface SecurityExceptionListener {
	
	void onSecurityException(User contact, Exception e);

}
