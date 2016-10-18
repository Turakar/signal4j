package de.thoffbauer.signal4j.store.serialize;

import java.io.IOException;

import org.whispersystems.libsignal.SignalProtocolAddress;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdKeySerializer;

@SuppressWarnings("serial")
public class SignalProtocolAddressSerializer extends StdKeySerializer {

	@Override
	public void serialize(Object value, JsonGenerator jgen, SerializerProvider provider) throws IOException {
		SignalProtocolAddress address = (SignalProtocolAddress) value;
		jgen.writeString(address.getName() + "." + address.getDeviceId());
	}

}
