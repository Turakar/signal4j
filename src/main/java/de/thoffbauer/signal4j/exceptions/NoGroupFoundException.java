package de.thoffbauer.signal4j.exceptions;

import de.thoffbauer.signal4j.store.GroupId;

@SuppressWarnings("serial")
public class NoGroupFoundException extends Exception {
	
	private GroupId id;

	public NoGroupFoundException(String message, GroupId id) {
		super(message);
		this.id = id;
	}

	public GroupId getId() {
		return id;
	}

}
