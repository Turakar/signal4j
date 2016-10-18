package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import org.whispersystems.libsignal.state.PreKeyRecord;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import de.thoffbauer.signal4j.util.Base64;

@SuppressWarnings("serial")
public class PreKeyRecordSerializer extends StdSerializer<PreKeyRecord> {

	public PreKeyRecordSerializer() {
		super(PreKeyRecord.class);
	}
	
	@Override
	public void serialize(PreKeyRecord value, JsonGenerator jgen, SerializerProvider provider)
			throws IOException, JsonGenerationException {
		jgen.writeString(Base64.encodeBytes(value.serialize()));
	}
	
}
