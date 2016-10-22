package de.thoffbauer.signal4j.store;

import java.util.ArrayList;

import org.whispersystems.signalservice.api.messages.multidevice.DeviceGroup;

public class Group {
	
	private GroupId id;
	private String name;
	private ArrayList<String> members;
	private boolean active;
	
	public Group() {
		
	}
	
	public Group(GroupId id) {
		this.id = id;
	}
	
	public Group(DeviceGroup of) {
		this.id = new GroupId(of.getId());
		this.name = of.getName().orNull();
		this.members = new ArrayList<>(of.getMembers());
		this.active = of.isActive();
	}

	public GroupId getId() {
		return id;
	}

	public void setId(GroupId id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public ArrayList<String> getMembers() {
		return members;
	}

	public void setMembers(ArrayList<String> members) {
		this.members = members;
	}

	public boolean isActive() {
		return active;
	}

	public void setActive(boolean active) {
		this.active = active;
	}

}
