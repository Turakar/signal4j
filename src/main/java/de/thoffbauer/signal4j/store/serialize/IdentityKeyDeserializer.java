package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.InvalidKeyException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import de.thoffbauer.signal4j.util.Base64;

@SuppressWarnings("serial")
public class IdentityKeyDeserializer extends StdDeserializer<IdentityKey> {

	public IdentityKeyDeserializer() {
		super(IdentityKey.class);
	}

	@Override
	public IdentityKey deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JsonProcessingException {
		try {
			return new IdentityKey(Base64.decode(p.getValueAsString()), 0);
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

}
