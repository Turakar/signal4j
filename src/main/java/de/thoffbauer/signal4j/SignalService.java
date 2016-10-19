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
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.state.PreKeyRecord;
import org.whispersystems.libsignal.state.SignedPreKeyRecord;
import org.whispersystems.libsignal.util.KeyHelper;
import org.whispersystems.libsignal.util.Medium;
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
	
	/**
	 * Path to main store file. Contains all keys etc.
	 */
	public static String STORE_PATH = "store.json";
	/**
	 * Folder to save attachments to
	 */
	public static String ATTACHMENTS_PATH = "attachments";
	
	private static final int PASSWORD_LENGTH = 18;
	private static final int SIGNALING_KEY_LENGTH = 52;
	private static final int MAX_REGISTRATION_ID = 8192;
	private static final int PREKEYS_BATCH_SIZE = 100;
	private static final int MAX_PREKEY_ID = Medium.MAX_VALUE;
	
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
	
	/**
	 * Create a new instance. Will automatically load a store file if existent.
	 * @throws IOException can be thrown while loading the store
	 */
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
	
	/**
	 * Starts the connection and registration as the primary device. This creates a new Signal account with this number.
	 * @param url the url of the signal server
	 * @param userAgent human-readable name of the user agent
	 * @param phoneNumber the user's phone number
	 * @param voice whether to call (true) or to message (false) for verification
	 * @throws IOException
	 */
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
	
	/**
	 * Finish the connection and registration as primary device with the received verification code
	 * @param verificationCode the verification code without the -
	 * @throws IOException
	 */
	public void finishConnectAsPrimary(String verificationCode) throws IOException {
		if(accountManager == null) {
			throw new IllegalStateException("Cannot finish: No connection started!");
		} else if(isRegistered()) {
			throw new IllegalStateException("Already registered!");
		}
		createRegistrationId();
		accountManager.verifyAccountWithCode(verificationCode, store.getSignalingKey(), 
				store.getLocalRegistrationId(), false);
		IdentityKeyPair identityKeyPair = KeyHelper.generateIdentityKeyPair();
		store.setIdentityKeyPair(identityKeyPair);
		store.setLastResortPreKey(KeyHelper.generateLastResortPreKey());
		checkPreKeys(-1);
		save();
	}
	
	/**
	 * Start connection and registration as secondary device. The device will be linked with the device scanning accepting the code.
	 * @param url the url of the signal server
	 * @param userAgent human-readable name of the user agent
	 * @param phoneNumber the user's phone number
	 * @return a url which must be shown as a QR code to the android app for provisioning
	 * @throws IOException
	 * @throws TimeoutException
	 */
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
	
	/**
	 * Blocking call. Call this directly after {@code startConnectAsSecondary()} and this method will wait
	 * for the master device accepting this device.
	 * @param deviceName a name for this device (not the user agent)
	 * @param supportsSms whether this device can receive and send SMS
	 * @throws IOException
	 * @throws TimeoutException
	 */
	public void finishConnectAsSecondary(String deviceName, boolean supportsSms) throws IOException, TimeoutException {
		if(accountManager == null) {
			throw new IllegalStateException("Cannot finish: No connection started!");
		} else if(isRegistered()) {
			throw new IllegalStateException("Already registered!");
		}
		try {
			NewDeviceRegistrationReturn ret = accountManager.finishNewDeviceRegistration(tempIdentity,
					store.getSignalingKey(), supportsSms, true, store.getLocalRegistrationId(), deviceName);
			store.setDeviceId(ret.getDeviceId());
			store.setIdentityKeyPair(ret.getIdentity());
		} catch (InvalidKeyException e) {
			throw new RuntimeException("This can not happen - theoretically", e);
		}
		store.setLastResortPreKey(KeyHelper.generateLastResortPreKey());
		checkPreKeys(-1);
		save();
	}

	/**
	 * Send a data, i.e. "normal" message
	 * @param address
	 * @param message
	 * @throws UntrustedIdentityException
	 * @throws IOException
	 */
	public void sendMessage(SignalServiceAddress address, SignalServiceDataMessage message) throws UntrustedIdentityException, IOException {
		checkRegistered();
		checkMessageSender();
		messageSender.sendMessage(address, message);
	}
	
	/**
	 * Request sync messages from primary device. They are received using the listeners
	 * @param types
	 * @throws IOException
	 * @throws UntrustedIdentityException
	 */
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
		if(!isRegistered()) {
			throw new IllegalStateException("Not registered!");
		}
	}

	/**
	 * Returns true if this device is registered. This does not necessarily 
	 * mean that no other device has registered with this number.
	 * @return whether this device is registered
	 */
	public boolean isRegistered() {
		return store.getIdentityKeyPair() != null;
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
	
	private void save() throws IOException {
		store.save(new File(STORE_PATH));
	}

	/**
	 * Add a listener for data, i.e. "normal" messages.
	 * The listener may be executed if a message arrives during {@code pull()}
	 * @param listener
	 */
	public void addDataMessageListener(DataMessageListener listener) {
		dataMessageListeners.add(listener);
	}
	
	/**
	 * Remove a data message listener
	 * @param listener
	 */
	public void removeDataMessageListener(DataMessageListener listener) {
		dataMessageListeners.remove(listener);
	}
	
	/**
	 * Add a listener for sync messages which are sent by the primary device.
	 * The listener may be executed if a message arrives during {@code pull()}
	 * @param listener
	 */
	public void addSyncMessageListener(SyncMessageListener listener) {
		syncMessageListeners.add(listener);
	}
	
	/**
	 * Remove a sync message listener
	 * @param listener
	 */
	public void removeSyncMessageListener(SyncMessageListener listener) {
		syncMessageListeners.remove(listener);
	}
	
	/**
	 * Wait for incoming messages. This method returns silently if the timeout passes.
	 * If a message arrives, the corresponding listeners are called and the method returns.
	 * @param timeoutMillis time to wait for messages
	 * @throws IOException
	 */
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
						file.delete();
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
						file.delete();
						for (SyncMessageListener listener : syncMessageListeners) {
							listener.onGroupsSync(groups);
						}
					} else if(syncMessage.getBlockedList().isPresent()) { // TODO: seems not to be working
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
	
	/**
	 * Ensures that there are enough prekeys available. Has to be called regularly.<br>
	 * Every time somebody sends you message, he uses one of your prekeys which you have uploaded earlier.
	 * To always have one prekey available, you also upload a last resort key. You should always
	 * have enough prekeys to prevent key reusing.
	 * @param minimumKeys the minimum amount of keys to register. Must be below 100.
	 * @throws IOException
	 */
	public void checkPreKeys(int minimumKeys) throws IOException {
		if(minimumKeys > PREKEYS_BATCH_SIZE) {
			throw new IllegalArgumentException("PreKeys count must be below or equal to " + PREKEYS_BATCH_SIZE);
		}
		checkRegistered();
		int preKeysCount = accountManager.getPreKeysCount();
		if(preKeysCount < minimumKeys || minimumKeys < 0) {
			try {
				// generate prekeys
				int nextPreKeyId = store.getNextPreKeyId();
				ArrayList<PreKeyRecord> preKeys = new ArrayList<>();
				for(int i = 0; i < PREKEYS_BATCH_SIZE; i++) {
		            PreKeyRecord record = new PreKeyRecord(nextPreKeyId, Curve.generateKeyPair());
		            store.storePreKey(record.getId(), record);
		            preKeys.add(record);
					nextPreKeyId = (nextPreKeyId + 1) % MAX_PREKEY_ID;
				}
				store.setNextPreKeyId(nextPreKeyId);
				
				// generate signed prekey
				int nextSignedPreKeyId = store.getNextSignedPreKeyId();
				SignedPreKeyRecord signedPreKey = KeyHelper.generateSignedPreKey(store.getIdentityKeyPair(), nextSignedPreKeyId);
				store.storeSignedPreKey(signedPreKey.getId(), signedPreKey);
				store.setNextSignedPreKeyId((nextSignedPreKeyId + 1) % MAX_PREKEY_ID);
				
				// upload
				accountManager.setPreKeys(store.getIdentityKeyPair().getPublicKey(), store.getLastResortPreKey(), 
						signedPreKey, preKeys);
			} catch (InvalidKeyException e) {
				throw new RuntimeException("Stored identity corrupt!", e);
			}
			save();
		}
	}
	
	/**
	 * Save an attachment to the attachments folder specified by {@code ATTACHMENTS_PATH}.
	 * The file name is chosen automatically based on the attachment id.
	 * @param attachment the attachment to download
	 * @param progressListener an optional download progress listener
	 * @return the file descriptor for the downloaded attachment
	 * @throws IOException
	 */
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
