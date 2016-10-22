package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.KeyDeserializer;

import de.thoffbauer.signal4j.store.GroupId;
import de.thoffbauer.signal4j.util.Base64;

public class GroupIdKeyDeserializer extends KeyDeserializer {

	@Override
	public Object deserializeKey(String key, DeserializationContext ctxt) throws IOException, JsonProcessingException {
		return new GroupId(Base64.decode(key));
	}

}
