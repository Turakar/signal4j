package de.thoffbauer.signal4j;

import java.io.File;
import java.io.IOException;
import java.net.URLEncoder;
import java.security.Security;
import java.util.Random;
import java.util.concurrent.TimeoutException;

import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.SignalServiceAccountManager.NewDeviceRegistrationReturn;
import org.whispersystems.signalservice.api.SignalServiceMessageSender;
import org.whispersystems.signalservice.api.crypto.UntrustedIdentityException;
import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.signalservice.api.messages.multidevice.RequestMessage;
import org.whispersystems.signalservice.api.messages.multidevice.SignalServiceSyncMessage;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.TrustStore;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.SyncMessage.Request;

import de.thoffbauer.signal4j.store.JsonSignalStore;
import de.thoffbauer.signal4j.store.WhisperTrustStore;
import de.thoffbauer.signal4j.util.Base64;
import de.thoffbauer.signal4j.util.SecretUtil;

public class SignalService {
	
	public static final String STORE_PATH = "store.json";
	private static final int PASSWORD_LENGTH = 18;
	private static final int SIGNALING_KEY_LENGTH = 52;
	private static final int MAX_REGISTRATION_ID = 8192;
	
	private final TrustStore trustStore = new WhisperTrustStore();
	
	private SignalServiceAccountManager accountManager;
	private SignalServiceMessageSender messageSender;
	private JsonSignalStore store;
	private IdentityKeyPair tempIdentity;
	
	public SignalService() throws IOException {
		// Add bouncycastle
		Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
		
		File storeFile = new File(STORE_PATH);
		if(storeFile.isFile()) {
			store = JsonSignalStore.load(storeFile);
			accountManager = new SignalServiceAccountManager(store.getUrl(), trustStore, store.getPhoneNumber(),
					store.getPassword(), store.getDeviceId(), store.getUserAgent());
		} else {
			store = new JsonSignalStore();
		}
	}
	
	public void startConnectAsPrimary(String url, String userAgent, String phoneNumber, boolean voice) throws IOException {
		if(accountManager != null) {
			throw new IllegalStateException("Already started a connection!");
		}
		store.setUrl(url);
		store.setUserAgent(userAgent);
		store.setPhoneNumber(phoneNumber);
		createPasswords();
		store.setDeviceId(SignalServiceAddress.DEFAULT_DEVICE_ID);
		accountManager = new SignalServiceAccountManager(url, trustStore, phoneNumber, 
				store.getPassword(), userAgent);
		if(voice) {
			accountManager.requestVoiceVerificationCode();
		} else {
			accountManager.requestSmsVerificationCode();
		}
	}
	
	public void finishConnectAsPrimary(String verificationCode) throws IOException {
		if(accountManager == null) {
			throw new IllegalStateException("Cannot finish: No connection started!");
		} else if(store.getIdentityKeyPair() != null) {
			throw new IllegalStateException("Already registered!");
		}
		createRegistrationId();
		accountManager.verifyAccountWithCode(verificationCode, store.getSignalingKey(), 
				store.getLocalRegistrationId(), false);
		IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
		store.setIdentityKeyPair(identityKeyPair);
	}
	
	public String startConnectAsSecondary(String url, String userAgent, String phoneNumber) throws IOException, TimeoutException {
		if(accountManager != null) {
			throw new IllegalStateException("Already started a connection!");
		}
		store.setUrl(url);
		store.setUserAgent(userAgent);
		store.setPhoneNumber(phoneNumber);
		createPasswords();
		createRegistrationId();
		accountManager = new SignalServiceAccountManager(url, trustStore, phoneNumber, 
				store.getPassword(), userAgent);
		String uuid = accountManager.getNewDeviceUuid();
		
		tempIdentity = KeyHelper.generateIdentityKeyPair();
		byte[] publicKeyBytes = tempIdentity.getPublicKey().serialize();
		String publicKeyBase64 = Base64.encodeBytesWithoutPadding(publicKeyBytes);

		String qrString = "tsdevice:/?uuid=" + URLEncoder.encode(uuid, "UTF-8") + 
				"&pub_key=" + URLEncoder.encode(publicKeyBase64, "UTF-8");
		return qrString;
	}
	
	public void finishConnectAsSecondary(String deviceName, boolean supportsSms) throws IOException, TimeoutException {
		try {
			NewDeviceRegistrationReturn ret = accountManager.finishNewDeviceRegistration(tempIdentity,
					store.getSignalingKey(), supportsSms, true, store.getLocalRegistrationId(), deviceName);
			store.setDeviceId(ret.getDeviceId());
			store.setIdentityKeyPair(ret.getIdentity());
		} catch (InvalidKeyException e) {
			throw new RuntimeException("This can not happen - theoretically", e);
		}
	}

	public void sendMessage(SignalServiceAddress address, SignalServiceDataMessage message) throws UntrustedIdentityException, IOException {
		checkRegistered();
		checkMessageSender();
		messageSender.sendMessage(address, message);
	}
	
	public void requestSync(Request.Type... types) throws IOException, UntrustedIdentityException {
		checkRegistered();
		checkMessageSender();
		for(Request.Type type : types) {
			RequestMessage request = new RequestMessage(Request.newBuilder().setType(type).build());
			SignalServiceSyncMessage syncMessage = SignalServiceSyncMessage.forRequest(request);
			messageSender.sendMessage(syncMessage);
		}
	}

	private void checkMessageSender() {
		if(messageSender == null) {
			messageSender = new SignalServiceMessageSender(store.getUrl(), trustStore, 
					store.getPhoneNumber(), store.getPassword(), store.getDeviceId(), store, 
					store.getUserAgent(), Optional.absent());
		}
	}
	
	private void checkRegistered() {
		if(isRegistered()) {
			throw new IllegalStateException("Not registered!");
		}
	}

	public boolean isRegistered() {
		return store.getIdentityKeyPair() == null;
	}
	
	private void createPasswords() {
		String password = SecretUtil.getSecret(PASSWORD_LENGTH);
		store.setPassword(password);
		String signalingKey= SecretUtil.getSecret(SIGNALING_KEY_LENGTH);
		store.setSignalingKey(signalingKey);
	}
	
	private void createRegistrationId() {
		int registrationId = new Random().nextInt(MAX_REGISTRATION_ID);
		store.setLocalRegistrationId(registrationId);
	}
	
	public void save() throws IOException {
		store.save(new File(STORE_PATH));
	}
	
}
