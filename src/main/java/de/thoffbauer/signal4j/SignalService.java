package de.thoffbauer.signal4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.IdentityKeyPair;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.NoSessionException;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.guava.Optional;
import org.whispersystems.signalservice.api.SignalServiceAccountManager;
import org.whispersystems.signalservice.api.SignalServiceAccountManager.NewDeviceRegistrationReturn;
import org.whispersystems.signalservice.api.SignalServiceMessagePipe;
import org.whispersystems.signalservice.api.SignalServiceMessageReceiver;
import org.whispersystems.signalservice.api.SignalServiceMessageSender;
import org.whispersystems.signalservice.api.crypto.SignalServiceCipher;
import org.whispersystems.signalservice.api.crypto.UntrustedIdentityException;
import org.whispersystems.signalservice.api.messages.SignalServiceAttachment;
import org.whispersystems.signalservice.api.messages.SignalServiceAttachment.ProgressListener;
import org.whispersystems.signalservice.api.messages.SignalServiceContent;
import org.whispersystems.signalservice.api.messages.SignalServiceDataMessage;
import org.whispersystems.signalservice.api.messages.SignalServiceEnvelope;
import org.whispersystems.signalservice.api.messages.multidevice.BlockedListMessage;
import org.whispersystems.signalservice.api.messages.multidevice.DeviceContact;
import org.whispersystems.signalservice.api.messages.multidevice.DeviceContactsInputStream;
import org.whispersystems.signalservice.api.messages.multidevice.DeviceGroup;
import org.whispersystems.signalservice.api.messages.multidevice.DeviceGroupsInputStream;
import org.whispersystems.signalservice.api.messages.multidevice.ReadMessage;
import org.whispersystems.signalservice.api.messages.multidevice.RequestMessage;
import org.whispersystems.signalservice.api.messages.multidevice.SentTranscriptMessage;
import org.whispersystems.signalservice.api.messages.multidevice.SignalServiceSyncMessage;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.push.TrustStore;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.SyncMessage.Request;

import de.thoffbauer.signal4j.listener.DataMessageListener;
import de.thoffbauer.signal4j.listener.SyncMessageListener;
import de.thoffbauer.signal4j.store.JsonSignalStore;
import de.thoffbauer.signal4j.store.WhisperTrustStore;
import de.thoffbauer.signal4j.util.Base64;
import de.thoffbauer.signal4j.util.SecretUtil;

public class SignalService {
	
	public static String STORE_PATH = "store.json";
	public static String ATTACHMENTS_PATH = "attachments";
	private static final int PASSWORD_LENGTH = 18;
	private static final int SIGNALING_KEY_LENGTH = 52;
	private static final int MAX_REGISTRATION_ID = 8192;
	
	private final TrustStore trustStore = new WhisperTrustStore();
	
	private SignalServiceAccountManager accountManager;
	private SignalServiceMessageSender messageSender;
	private SignalServiceMessagePipe messagePipe;
	private SignalServiceMessageReceiver messageReceiver;
	private SignalServiceCipher cipher;
	private JsonSignalStore store;
	private IdentityKeyPair tempIdentity;
	
	private ArrayList<DataMessageListener> dataMessageListeners = new ArrayList<>();
	private ArrayList<SyncMessageListener> syncMessageListeners = new ArrayList<>();
	
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
	
	public void quit() throws IOException {
		store.save(new File(STORE_PATH));
	}

	
	public void addDataMessageListener(DataMessageListener listener) {
		dataMessageListeners.add(listener);
	}
	

	public void removeDataMessageListener(DataMessageListener listener) {
		dataMessageListeners.remove(listener);
	}
	
	public void addSyncMessageListener(SyncMessageListener listener) {
		syncMessageListeners.add(listener);
	}
	
	public void removeSyncMessageListener(SyncMessageListener listener) {
		syncMessageListeners.remove(listener);
	}
	
	public void pull(int timeoutMillis) throws IOException {
		checkRegistered();
		if(messagePipe == null) {
			messageReceiver = new SignalServiceMessageReceiver(store.getUrl(), 
					trustStore, store.getPhoneNumber(), store.getPassword(), store.getDeviceId(), 
					store.getSignalingKey(), store.getUserAgent());
			messagePipe = messageReceiver.createMessagePipe();
		}
		try {
			SignalServiceEnvelope envelope;
			try {
				envelope = messagePipe.read(timeoutMillis, TimeUnit.MILLISECONDS);
			} catch (TimeoutException e) {
				return;
			}
			if(!envelope.isReceipt() && (envelope.hasContent() || envelope.hasLegacyMessage())) {
				if(cipher == null) {
					cipher = new SignalServiceCipher(new SignalServiceAddress(store.getPhoneNumber()), store);
				}
				SignalServiceContent content = cipher.decrypt(envelope);
				if(content.getDataMessage().isPresent()) {
					SignalServiceDataMessage dataMessage = content.getDataMessage().get();
					for(DataMessageListener listener : dataMessageListeners) {
						listener.onMessageReceived(envelope.getSourceAddress(), dataMessage);
					}
				} else if(content.getSyncMessage().isPresent()) {
					SignalServiceSyncMessage syncMessage = content.getSyncMessage().get();
					if(syncMessage.getContacts().isPresent()) {
						File file = saveAttachment(syncMessage.getContacts().get(), null);
						DeviceContactsInputStream in = new DeviceContactsInputStream(new FileInputStream(file));
						ArrayList<DeviceContact> contacts = new ArrayList<>();
						try {
							while(true) {
								contacts.add(in.read());
							}
						} catch(IOException e) {
							// we have to assume that we have an EOF here
						}
						for(SyncMessageListener listener : syncMessageListeners) {
							listener.onContactsSync(contacts);
						}
					} else if(syncMessage.getGroups().isPresent()) {
						File file = saveAttachment(syncMessage.getGroups().get(), null);
						DeviceGroupsInputStream in = new DeviceGroupsInputStream(new FileInputStream(file));
						ArrayList<DeviceGroup> groups = new ArrayList<>();
						try {
							while(true) {
								groups.add(in.read());
							}
						} catch(IOException e) {
							// we have to assume that we have an EOF here
						}
						for (SyncMessageListener listener : syncMessageListeners) {
							listener.onGroupsSync(groups);
						}
					} else if(syncMessage.getBlockedList().isPresent()) {
						BlockedListMessage blockedMessage = syncMessage.getBlockedList().get();
						for (SyncMessageListener syncMessageListener : syncMessageListeners) {
							syncMessageListener.onBlockedSync(blockedMessage.getNumbers());
						}
					} else if(syncMessage.getRead().isPresent()) {
						List<ReadMessage> reads = syncMessage.getRead().get();
						for (SyncMessageListener listener : syncMessageListeners) {
							listener.onReadSync(reads);
						}
					} else if(syncMessage.getSent().isPresent()) {
						SentTranscriptMessage transcript = syncMessage.getSent().get();
						for (SyncMessageListener listener : syncMessageListeners) {
							listener.onTranscriptSync(transcript);
						}
					} //TODO: implement requests
				}
			}
		} catch (InvalidVersionException | InvalidMessageException | InvalidKeyException | DuplicateMessageException | InvalidKeyIdException | org.whispersystems.libsignal.UntrustedIdentityException | LegacyMessageException | NoSessionException e) {
			throw new RuntimeException("We got a message with an incompatible version", e);
			//TODO: security exceptions handling
		}
		
	}
	
	public void checkPreKeys(int minimumKeys) throws IOException {
		checkRegistered();
		int preKeysCount = accountManager.getPreKeysCount();
		if(preKeysCount < minimumKeys) {
			
		}
	}
	
	public File saveAttachment(SignalServiceAttachment attachment, ProgressListener progressListener)
			throws IOException {
		File attachmentsDir = new File(ATTACHMENTS_PATH);
		if(!attachmentsDir.exists()) {
			boolean success = attachmentsDir.mkdirs();
			if(!success) {
				throw new IOException("Could not create attachments directory!");
			}
		}
		String attachmentId = String.valueOf(attachment.asPointer().getId());
		File file = Paths.get(attachmentsDir.getAbsolutePath(), attachmentId).toFile();
		if(file.exists()) {
			return file;
		}
		File buffer = Paths.get(attachmentsDir.getAbsolutePath(), attachmentId + ".part").toFile();
		try {
			InputStream in = messageReceiver.retrieveAttachment(attachment.asPointer(), buffer, progressListener);
			Files.copy(in, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
			buffer.delete();
		} catch (InvalidMessageException e) {
			throw new RuntimeException(e);
			//TODO: exception handling
		}
		return file;
	}
	
}
