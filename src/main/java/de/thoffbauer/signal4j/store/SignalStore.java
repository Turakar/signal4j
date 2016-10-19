package de.thoffbauer.signal4j.store;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.state.SessionRecord;
import org.whispersystems.libsignal.state.SignalProtocolStore;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;

import com.fasterxml.jackson.annotation.JsonIgnore;

public abstract class SignalStore implements SignalProtocolStore {

	public abstract IdentityKey getIdentity(String name);
	
	@Override
	@JsonIgnore
	public boolean isTrustedIdentity(String name, IdentityKey identityKey) {
		IdentityKey storedIdentity = getIdentity(name);
		return storedIdentity == null || identityKey.equals(storedIdentity);
	}
	
	public abstract Iterable<Entry<SignalProtocolAddress, SessionRecord>> getSessions();
	
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
	
	public abstract SessionRecord getSession(SignalProtocolAddress address);
	
	@Override
	public SessionRecord loadSession(SignalProtocolAddress address) {
		SessionRecord session = getSession(address);
		if(session == null) {
			session = new SessionRecord();
		}
		return session;
	}
}
