package de.thoffbauer.signal4j.listener;

import de.thoffbauer.signal4j.store.User;

public interface SecurityExceptionListener {
	
	/**
	 * Called if a security relevant exception rises during message decrypting or attachment downloading.
	 * The message will not be forwarded to the conversation listeners.
	 * @param user the user from whom the invalid message came
	 * @param e one of InvalidVersionException, InvalidMessageException, InvalidKeyException, DuplicateMessageException, InvalidKeyIdException, UntrustedIdentityException, UnregisteredUserException or LegacyMessageException
	 */
	void onSecurityException(User user, Exception e);

}
