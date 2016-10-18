package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

import de.thoffbauer.signal4j.util.Base64;

@SuppressWarnings("serial")
public class IdentityKeyPairDeserializer extends StdDeserializer<IdentityKeyPair> {

	public IdentityKeyPairDeserializer() {
		super(IdentityKeyPair.class);
	}

	@Override
	public IdentityKeyPair deserialize(JsonParser p, DeserializationContext ctxt)
			throws IOException, JsonProcessingException {
		String bytes = p.getValueAsString();
		try {
			return new IdentityKeyPair(Base64.decode(bytes));
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

}
