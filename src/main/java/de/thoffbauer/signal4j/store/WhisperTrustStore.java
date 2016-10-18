package de.thoffbauer.signal4j.store;


import java.io.InputStream;

import org.whispersystems.signalservice.api.push.TrustStore;

public class WhisperTrustStore implements TrustStore {

    @Override
    public InputStream getKeyStoreInputStream() {
        InputStream in = WhisperTrustStore.class.getResourceAsStream("whisper.store");
        if(in == null) {
        	throw new RuntimeException("Could not load whisper store!");
        }
		return in;
    }

    @Override
    public String getKeyStorePassword() {
        return "whisper";
    }
}
