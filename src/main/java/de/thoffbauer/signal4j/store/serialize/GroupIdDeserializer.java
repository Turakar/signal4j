package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import de.thoffbauer.signal4j.store.GroupId;
import de.thoffbauer.signal4j.util.Base64;

@SuppressWarnings("serial")
public class GroupIdDeserializer extends StdDeserializer<GroupId> {

	public GroupIdDeserializer() {
		super(GroupId.class);
	}
	
	@Override
	public GroupId deserialize(JsonParser p, DeserializationContext ctxt) throws IOException, JsonProcessingException {
		return new GroupId(Base64.decode(p.getValueAsString()));
	}
	
}
