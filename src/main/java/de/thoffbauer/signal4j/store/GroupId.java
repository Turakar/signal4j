package de.thoffbauer.signal4j.store;

import java.util.Arrays;

public class GroupId {
	
	public static final int LENGTH = 16;
	
	private final byte[] id;

	public GroupId(byte[] id) {
		this.id = id;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + Arrays.hashCode(id);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		GroupId other = (GroupId) obj;
		if (!Arrays.equals(id, other.id))
			return false;
		return true;
	}

	public byte[] getId() {
		return id;
	}

}
