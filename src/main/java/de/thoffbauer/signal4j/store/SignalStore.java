package de.thoffbauer.signal4j.store;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;

import com.fasterxml.jackson.annotation.JsonIgnore;

public abstract class SignalStore implements SignalProtocolStore {
	
	@Override
	@JsonIgnore
	public boolean isTrustedIdentity(String name, IdentityKey identityKey) {
		IdentityKey storedIdentity = getIdentity(name);
		return storedIdentity == null || identityKey.equals(storedIdentity);
	}
	
	@Override
	@JsonIgnore
	public List<Integer> getSubDeviceSessions(String name) {
		List<Integer> ids = new ArrayList<Integer>();
		for(Entry<SignalProtocolAddress, SessionRecord> entry : getSessions()) {
			SignalProtocolAddress address = entry.getKey();
			if(address.getName().equals(name) && 
					address.getDeviceId() != SignalServiceAddress.DEFAULT_DEVICE_ID) {
				ids.add(address.getDeviceId());
			}
		}
		return ids;
	}
	
	@Override
	public void deleteAllSessions(String name) {
		for(Iterator<Entry<SignalProtocolAddress, SessionRecord>> it = getSessions().iterator(); 
				it.hasNext();) {
			if(it.next().getKey().getName().equals(name)) {
				it.remove();
			}
		}
	}
	
	
	@Override
	public SessionRecord loadSession(SignalProtocolAddress address) {
		SessionRecord session = getSession(address);
		if(session == null) {
			session = new SessionRecord();
		}
		return session;
	}

	public abstract void save(File file) throws IOException;
	
	public abstract DataStore getDataStore();

	public abstract IdentityKey getIdentity(String name);
	public abstract Iterable<Entry<SignalProtocolAddress, SessionRecord>> getSessions();
	public abstract SessionRecord getSession(SignalProtocolAddress address);
	
	public abstract String getUrl();
	public abstract void setUrl(String url);
	public abstract String getUserAgent();
	public abstract void setUserAgent(String userAgent);
	public abstract String getPhoneNumber();
	public abstract void setPhoneNumber(String phoneNumber);
	public abstract void setIdentityKeyPair(IdentityKeyPair identityKeyPair);
	public abstract String getPassword();
	public abstract void setPassword(String password);
	public abstract String getSignalingKey();
	public abstract void setSignalingKey(String signalingKey);
	public abstract int getDeviceId();
	public abstract void setDeviceId(int deviceId);
	public abstract PreKeyRecord getLastResortPreKey();
	public abstract void setLastResortPreKey(PreKeyRecord lastResortPreKey);
	public abstract void setLocalRegistrationId(int localRegistrationId);
	public abstract int getNextPreKeyId();
	public abstract void setNextPreKeyId(int nextPreKeyId);
	public abstract int getNextSignedPreKeyId();
	public abstract void setNextSignedPreKeyId(int nextSignedPreKeyId);
}
