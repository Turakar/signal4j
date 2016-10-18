package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import org.whispersystems.libsignal.state.SessionRecord;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import de.thoffbauer.signal4j.util.Base64;

@SuppressWarnings("serial")
public class SessionRecordDeserializer extends StdDeserializer<SessionRecord> {

	public SessionRecordDeserializer() {
		super(SessionRecord.class);
	}
	
	@Override
	public SessionRecord deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JsonProcessingException {
		return new SessionRecord(Base64.decode(p.getValueAsString()));
	}
	
}
