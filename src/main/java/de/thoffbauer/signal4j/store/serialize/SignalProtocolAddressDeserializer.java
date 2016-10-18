package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import org.whispersystems.libsignal.SignalProtocolAddress;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.KeyDeserializer;

public class SignalProtocolAddressDeserializer extends KeyDeserializer {

	@Override
	public Object deserializeKey(String key, DeserializationContext ctxt) throws IOException, JsonProcessingException {
		String[] split = key.split("\\.");
		return new SignalProtocolAddress(split[0], Integer.valueOf(split[1]));
	}
	
}
