package de.thoffbauer.signal4j.store;

import java.util.HashMap;

import org.whispersystems.signalservice.api.messages.multidevice.DeviceContact;

import com.fasterxml.jackson.annotation.JsonProperty;

public class JsonDataStore {
	
	// TODO: save groups and contacts and associate them with messages
	
	@JsonProperty
	private HashMap<String, DeviceContact> contacts = new HashMap<>();
	

}
