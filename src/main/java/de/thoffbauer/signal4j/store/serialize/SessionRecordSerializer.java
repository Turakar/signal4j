package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import org.whispersystems.libsignal.state.SessionRecord;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import de.thoffbauer.signal4j.util.Base64;

@SuppressWarnings("serial")
public class SessionRecordSerializer extends StdSerializer<SessionRecord> {

	public SessionRecordSerializer() {
		super(SessionRecord.class);
	}
	
	@Override
	public void serialize(SessionRecord value, JsonGenerator jgen, SerializerProvider provider)
			throws IOException, JsonGenerationException {
		jgen.writeString(Base64.encodeBytes(value.serialize()));
	}

}
