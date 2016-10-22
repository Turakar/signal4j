package de.thoffbauer.signal4j.store;

import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.List;

public abstract class DataStore {

	//TODO: add avatar support for groups and contacts
	
	public abstract User getContact(String number);
	public abstract void addContact(User contact);
	public abstract void overwriteContacts(List<User> contacts);
	public abstract Collection<User> getContacts();
	
	public abstract Group getGroup(GroupId id);
	public abstract void addGroup(Group group);
	public abstract void overwriteGroups(List<Group> groups);
	public abstract Collection<Group> getGroups();
	
	public abstract void save(File file) throws IOException;
	
}
