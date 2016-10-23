package de.thoffbauer.signal4j.store;

import org.whispersystems.signalservice.api.messages.multidevice.DeviceContact;

public class User {
	
	private String number;
	private String name;
	private String avatarId;
	private String color;
	private boolean blocked = false;
	
	public User() {
		
	}
	
	public User(String number) {
		this.number = number;
	}
	
	public User(DeviceContact of) {
		this.number = of.getNumber();
		this.name = of.getName().orNull();
		this.color = of.getColor().orNull();
	}

	public String getNumber() {
		return number;
	}

	public void setNumber(String number) {
		this.number = number;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getColor() {
		return color;
	}

	public void setColor(String color) {
		this.color = color;
	}

	public boolean isBlocked() {
		return blocked;
	}

	public void setBlocked(boolean blocked) {
		this.blocked = blocked;
	}

	public String getAvatarId() {
		return avatarId;
	}

	public void setAvatarId(String avatarId) {
		this.avatarId = avatarId;
	}

}
