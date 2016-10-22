package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import de.thoffbauer.signal4j.store.GroupId;
import de.thoffbauer.signal4j.util.Base64;

@SuppressWarnings("serial")
public class GroupIdSerializer extends StdSerializer<GroupId> {

	public GroupIdSerializer() {
		super(GroupId.class);
	}
	
	@Override
	public void serialize(GroupId value, JsonGenerator jgen, SerializerProvider provider)
			throws IOException, JsonGenerationException {
		jgen.writeString(Base64.encodeBytes(value.getId()));
	}
	
}
