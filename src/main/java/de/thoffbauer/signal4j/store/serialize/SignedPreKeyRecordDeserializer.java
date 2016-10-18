package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import org.whispersystems.libsignal.state.SignedPreKeyRecord;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import de.thoffbauer.signal4j.util.Base64;

@SuppressWarnings("serial")
public class SignedPreKeyRecordDeserializer extends StdDeserializer<SignedPreKeyRecord> {

	public SignedPreKeyRecordDeserializer() {
		super(SignedPreKeyRecord.class);
	}
	
	@Override
	public SignedPreKeyRecord deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JsonProcessingException {
		return new SignedPreKeyRecord(Base64.decode(p.getValueAsString()));
	}
}
