package de.thoffbauer.signal4j.store;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonDataStore extends DataStore {
	
	@JsonProperty
	private HashMap<String, User> contacts = new HashMap<>();
	@JsonProperty
	private HashMap<GroupId, Group> groups = new HashMap<>();

	@Override
	public void save(File file) throws IOException {
		ObjectMapper mapper = new ObjectMapper();
		mapper.writeValue(file, this);
	}

	@Override
	public User getContact(String number) {
		return contacts.get(number);
	}

	@Override
	public void addContact(User contact) {
		contacts.put(contact.getNumber(), contact);
	}

	@Override
	public void overwriteContacts(List<User> contacts) {
		this.contacts.clear();
		for(User contact : contacts) {
			addContact(contact);
		}
	}
	
	@Override
	@JsonIgnore
	public Collection<User> getContacts() {
		return contacts.values();
	}

	@Override
	public Group getGroup(GroupId id) {
		return groups.get(id);
	}

	@Override
	public void addGroup(Group group) {
		groups.put(group.getId(), group);
	}

	@Override
	public void overwriteGroups(List<Group> groups) {
		this.groups.clear();
		for(Group group : groups) {
			addGroup(group);
		}
	}
	
	@Override
	@JsonIgnore
	public Collection<Group> getGroups() {
		return groups.values();
	}

}
