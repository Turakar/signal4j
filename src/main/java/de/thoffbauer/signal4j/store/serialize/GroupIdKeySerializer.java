package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdKeySerializer;

import de.thoffbauer.signal4j.store.GroupId;
import de.thoffbauer.signal4j.util.Base64;

@SuppressWarnings("serial")
public class GroupIdKeySerializer extends StdKeySerializer {

	@Override
	public void serialize(Object value, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		GroupId id = (GroupId) value;
		jgen.writeFieldName(Base64.encodeBytes(id.getId()));
	}
	
}
