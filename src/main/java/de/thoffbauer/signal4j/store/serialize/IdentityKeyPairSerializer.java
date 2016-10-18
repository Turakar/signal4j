package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import org.whispersystems.libsignal.IdentityKeyPair;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import de.thoffbauer.signal4j.util.Base64;

@SuppressWarnings("serial")
public class IdentityKeyPairSerializer extends StdSerializer<IdentityKeyPair> {

	public IdentityKeyPairSerializer() {
		super(IdentityKeyPair.class);
	}

	@Override
	public void serialize(IdentityKeyPair value, JsonGenerator jgen, SerializerProvider provider)
			throws IOException, JsonGenerationException {
		jgen.writeString(Base64.encodeBytes(value.serialize()));
	}
	
}
