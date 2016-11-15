package de.thoffbauer.signal4j;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

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
import org.whispersystems.signalservice.api.messages.SignalServiceGroup;
import org.whispersystems.signalservice.api.messages.SignalServiceGroup.Type;
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
import org.whispersystems.signalservice.api.push.exceptions.EncapsulatedExceptions;
import org.whispersystems.signalservice.api.push.exceptions.UnregisteredUserException;
import org.whispersystems.signalservice.internal.push.SignalServiceProtos.SyncMessage.Request;

import de.thoffbauer.signal4j.exceptions.NoGroupFoundException;
import de.thoffbauer.signal4j.listener.ConversationListener;
import de.thoffbauer.signal4j.listener.SecurityExceptionListener;
import de.thoffbauer.signal4j.store.DataStore;
import de.thoffbauer.signal4j.store.Group;
import de.thoffbauer.signal4j.store.GroupId;
import de.thoffbauer.signal4j.store.JsonSignalStore;
import de.thoffbauer.signal4j.store.SignalStore;
import de.thoffbauer.signal4j.store.User;
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
	private SignalStore store;
	private IdentityKeyPair tempIdentity;
	
	private ArrayList<ConversationListener> conversationListeners = new ArrayList<>();
	private ArrayList<SecurityExceptionListener> securityExceptionListeners = new ArrayList<>();
	
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
				store.getLocalRegistrationId(), false, true);
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
	 * @throws IOException
	 */
	public void sendMessage(String address, SignalServiceDataMessage message) throws IOException {
		checkRegistered();
		checkMessageSender();
		try {
			messageSender.sendMessage(new SignalServiceAddress(address), message);
		} catch (UntrustedIdentityException e) {
			fireSecurityException(new SignalServiceAddress(address), e);
		}
		save();
	}
	
	/**
	 * Send a data, i.e. "normal" message to a group
	 * @param addresses
	 * @param message
	 * @throws IOException
	 */
	public void sendMessage(List<String> addresses, SignalServiceDataMessage message) throws IOException {
		checkRegistered();
		checkMessageSender();
		List<SignalServiceAddress> signalServiceAddresses = addresses.stream()
				.filter(v -> !v.equals(store.getPhoneNumber()))
				.map(v -> new SignalServiceAddress(v))
				.collect(Collectors.toList());
		try {
			messageSender.sendMessage(signalServiceAddresses, message);
		} catch (EncapsulatedExceptions e) {
			for(UntrustedIdentityException ex : e.getUntrustedIdentityExceptions()) {
				fireSecurityException(new SignalServiceAddress(ex.getE164Number()), ex);
			}
			for(UnregisteredUserException ex : e.getUnregisteredUserExceptions()) {
				fireSecurityException(new SignalServiceAddress(ex.getE164Number()), ex);
			}
			if(!e.getNetworkExceptions().isEmpty()) {
				throw new IOException(e.getNetworkExceptions().size() + " network exception(s)! One is following.", 
						e.getNetworkExceptions().get(0));
			}
		}
		save();
	}
	
	/**
	 * Notify other devices that these messages have been read.
	 * @param messages
	 * @throws IOException
	 */
	public void markRead(List<ReadMessage> messages) throws IOException {
		checkRegistered();
		checkMessageSender();
		try {
			SignalServiceSyncMessage syncMessage = SignalServiceSyncMessage.forRead(messages);
			messageSender.sendMessage(syncMessage);
		} catch (UntrustedIdentityException e) {
			fireSecurityException(new SignalServiceAddress(store.getPhoneNumber()), e);
		}
	}
	
	/**
	 * Request sync messages from primary device. They are received using the listeners
	 * @throws IOException
	 * @throws UntrustedIdentityException
	 */
	public void requestSync() throws IOException {
		try {
			checkRegistered();
			checkMessageSender();
			Request.Type[] types = new Request.Type[] {Request.Type.CONTACTS, Request.Type.GROUPS, Request.Type.BLOCKED};
			for(Request.Type type : types) {
				RequestMessage request = new RequestMessage(Request.newBuilder().setType(type).build());
				SignalServiceSyncMessage syncMessage = SignalServiceSyncMessage.forRequest(request);
				messageSender.sendMessage(syncMessage);
			}
		} catch(UntrustedIdentityException e) {
			fireSecurityException(new SignalServiceAddress(store.getPhoneNumber()), e);
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
	
	/**
	 * Saves the store. As this is done automatically inside the library, 
	 * you only need to call this if you change sometihng manually.
	 * @throws IOException
	 */
	public void save() throws IOException {
		store.save(new File(STORE_PATH));
	}

	public void addConversationListener(ConversationListener listener) {
		conversationListeners.add(listener);
	}
	
	public void removeConversationListener(ConversationListener listener) {
		conversationListeners.remove(listener);
	}
	
	/**
	 * Add a listener for exceptions regarding the security of communication.
	 * @param listener
	 */
	public void addSecurityExceptionListener(SecurityExceptionListener listener) {
		securityExceptionListeners.add(listener);
	}
	
	/**
	 * Remove a security exception listener
	 * @param listener
	 */
	public void removeSecurityExceptionListener(SecurityExceptionListener listener) {
		securityExceptionListeners.remove(listener);
	}
	
	/**
	 * Wait for incoming messages. This method returns silently if the timeout passes.
	 * If a message arrives, the conversation listeners are called and the method returns.
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
		SignalServiceEnvelope envelope = null;
		try {
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
					handleDataMessage(envelope, dataMessage);
				} else if(content.getSyncMessage().isPresent()) {
					SignalServiceSyncMessage syncMessage = content.getSyncMessage().get();
					handleSyncMessage(envelope, syncMessage);
				}
			}
			save();
		} catch (InvalidVersionException | InvalidMessageException | InvalidKeyException | DuplicateMessageException | InvalidKeyIdException | org.whispersystems.libsignal.UntrustedIdentityException | LegacyMessageException e) {
			fireSecurityException(envelope != null ? envelope.getSourceAddress() : null, e);
		} catch(NoSessionException e) {
			throw new RuntimeException("The store file seems to be corrupt!", e);
		}
	}

	private void handleDataMessage(SignalServiceEnvelope envelope, SignalServiceDataMessage dataMessage) throws IOException {
		if(dataMessage.getGroupInfo().isPresent()) {
			SignalServiceGroup groupInfo = dataMessage.getGroupInfo().get();
			GroupId id = new GroupId(groupInfo.getGroupId());
			Group group = store.getDataStore().getGroup(id);
			if(groupInfo.getType() == SignalServiceGroup.Type.UPDATE) {
				if(group == null) {
					group = new Group(id);
					group.setActive(true);
					store.getDataStore().addGroup(group);
				}
				if(groupInfo.getName().isPresent()) {
					group.setName(groupInfo.getName().get());
				}
				if(groupInfo.getMembers().isPresent()) {
					group.setMembers(new ArrayList<>(groupInfo.getMembers().get()));
				}
				if(groupInfo.getAvatar().isPresent()) {
					SignalServiceAttachment attachment = groupInfo.getAvatar().get();
					String avatarId = UUID.randomUUID().toString();
					saveAttachment(toUser(envelope.getSourceAddress()), attachment, null, avatarId);
					if(group.getAvatarId() != null) {
						deleteAttachment(group.getAvatarId());
					}
					group.setAvatarId(avatarId);
				}
				fireGroupUpdate(envelope.getSourceAddress(), group);
			} else if(groupInfo.getType() == SignalServiceGroup.Type.QUIT) {
				if(group != null) {
					if(envelope.getSourceAddress().getNumber().equals(store.getPhoneNumber())) {
						group.setActive(false);
					}
					group.getMembers().remove(envelope.getSourceAddress().getNumber());
					fireGroupUpdate(envelope.getSourceAddress(), group);
				}
			} else {
				if(group == null) {
					fireSecurityException(envelope.getSourceAddress(), new NoGroupFoundException("No group known for ID", id));
				}
				fireMessage(envelope.getSourceAddress(), dataMessage, group);
			}
		} else {
			fireMessage(envelope.getSourceAddress(), dataMessage, null);
		}
	}

	private void handleSyncMessage(SignalServiceEnvelope envelope, SignalServiceSyncMessage syncMessage)
			throws IOException, FileNotFoundException {
		if(syncMessage.getContacts().isPresent()) {
			File file = saveAttachment(envelope.getSourceAddress(), syncMessage.getContacts().get(), null);
			DeviceContactsInputStream in = new DeviceContactsInputStream(new FileInputStream(file));
			ArrayList<User> contacts = new ArrayList<>();
			while(true) {
				DeviceContact deviceContact = in.read();
				if(deviceContact == null) {
					//EOF
					break;
				}
				User contact = new User(deviceContact);
				contacts.add(contact);
				if(deviceContact.getAvatar().isPresent()) {
					String id = UUID.randomUUID().toString();
					saveAttachment(toUser(envelope.getSourceAddress()), deviceContact.getAvatar().get(), 
							null, id);
					contact.setAvatarId(id);
				}
			}
			file.delete();
			store.getDataStore().getContacts().stream()
					.filter(v -> v.getAvatarId() != null)
					.forEach(v -> deleteAttachment(v.getAvatarId()));
			store.getDataStore().overwriteContacts(contacts);
			for(User contact : contacts) {
				fireContactUpdate(contact);
			}
		} else if(syncMessage.getGroups().isPresent()) {
			File file = saveAttachment(envelope.getSourceAddress(), syncMessage.getGroups().get(), null);
			DeviceGroupsInputStream in = new DeviceGroupsInputStream(new FileInputStream(file));
			List<Group> groups = new ArrayList<>();
			while(true) {
				DeviceGroup deviceGroup = in.read();
				if(deviceGroup == null) {
					//EOF
					break;
				}
				Group group = new Group(deviceGroup);
				groups.add(group);
				if(deviceGroup.getAvatar().isPresent()) {
					String id = UUID.randomUUID().toString();
					saveAttachment(toUser(envelope.getSourceAddress()), deviceGroup.getAvatar().get(), 
							null, id);
					group.setAvatarId(id);
				}
			}
			file.delete();
			store.getDataStore().getGroups().stream()
					.filter(v -> v.getAvatarId() != null)
					.forEach(v -> deleteAttachment(v.getAvatarId()));
			store.getDataStore().overwriteGroups(groups);
			for(Group group : groups) {
				fireGroupUpdate(envelope.getSourceAddress(), group);
			}
		} else if(syncMessage.getBlockedList().isPresent()) {
			BlockedListMessage blockedMessage = syncMessage.getBlockedList().get();
			List<String> blocked = blockedMessage.getNumbers();
			for(User contact : store.getDataStore().getContacts()) {
				boolean isNewBlocked = blocked.contains(contact.getNumber());
				if(contact.isBlocked() && !isNewBlocked) {
					contact.setBlocked(false);
					fireContactUpdate(contact);
				} else if(!contact.isBlocked() && isNewBlocked) {
					contact.setBlocked(true);
					fireContactUpdate(contact);
				}
			}
		} else if(syncMessage.getRead().isPresent()) {
			List<ReadMessage> reads = syncMessage.getRead().get();
			fireReadUpdate(reads);
		} else if(syncMessage.getSent().isPresent()) {
			SentTranscriptMessage transcript = syncMessage.getSent().get();
			handleDataMessage(envelope, transcript.getMessage());
		}
	}
	
	private void fireContactUpdate(User contact) throws IOException {
		for(ConversationListener listener : conversationListeners) {
			listener.onContactUpdate(contact);
		}
	}

	private void fireMessage(SignalServiceAddress address, SignalServiceDataMessage dataMessage, Group group) {
		for(ConversationListener listener : conversationListeners) {
			listener.onMessage(toUser(address), dataMessage, group);
		}
	}

	private void fireGroupUpdate(SignalServiceAddress address, Group group) throws IOException {
		for(ConversationListener listener : conversationListeners) {
			listener.onGroupUpdate(toUser(address), group);
		}
	}
	
	private void fireReadUpdate(List<ReadMessage> readList) {
		for(ConversationListener listener : conversationListeners) {
			listener.onReadUpdate(readList);
		}
	}
	
	private void fireSecurityException(SignalServiceAddress sender, Exception e) {
		fireSecurityException(toUser(sender), e);
	}
	
	private void fireSecurityException(User sender, Exception e) {
		for(SecurityExceptionListener listener : securityExceptionListeners) {
			listener.onSecurityException(sender, e);
		}
	}
	
	/**
	 * Tries to find the address in the stored contacts and creates new user if necessary (but does not store it).
	 * @param address
	 * @return the found contact or the new user
	 */
	public User toUser(SignalServiceAddress address) {
		if(address == null) {
			return null;
		}
		User user = store.getDataStore().getContact(address.getNumber());
		if(user == null) {
			user = new User(address.getNumber());
		}
		return user;
	}
	
	/**
	 * Ensures that there are enough prekeys available. Has to be called regularly.<br>
	 * Every time somebody sends you a message, he uses one of your prekeys which you have uploaded earlier.
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
	 * @param sender for mapping an exception which might occur to the sender
	 * @param attachment the attachment to download
	 * @param progressListener an optional download progress listener
	 * @return the file descriptor for the saved attachment
	 * @throws IOException
	 */
	public File saveAttachment(SignalServiceAddress sender, SignalServiceAttachment attachment, ProgressListener progressListener)
			throws IOException {
		return saveAttachment(toUser(sender), attachment, progressListener);
	}
	/**
	 * Save an attachment to the attachments folder specified by {@code ATTACHMENTS_PATH}.
	 * The file name is chosen automatically based on the attachment id.
	 * @param sender for mapping an exception which might occur to the sender
	 * @param attachment the attachment to download
	 * @param progressListener an optional download progress listener
	 * @return the file descriptor for the saved attachment
	 * @throws IOException
	 */
	public File saveAttachment(User sender, SignalServiceAttachment attachment, ProgressListener progressListener)
			throws IOException {
		String attachmentId = String.valueOf(attachment.asPointer().getId());
		return saveAttachment(sender, attachment, progressListener, attachmentId);
	}
	private File saveAttachment(User sender, SignalServiceAttachment attachment, 
			ProgressListener progressListener, String attachmentId) throws IOException {
		File attachmentsDir = new File(ATTACHMENTS_PATH);
		if(!attachmentsDir.exists()) {
			boolean success = attachmentsDir.mkdirs();
			if(!success) {
				throw new IOException("Could not create attachments directory!");
			}
		}
		File file = Paths.get(attachmentsDir.getAbsolutePath(), attachmentId).toFile();
		if(file.exists()) {
			return file;
		}
		File buffer = Paths.get(attachmentsDir.getAbsolutePath(), attachmentId + ".part").toFile();
		InputStream in = null;
		if(attachment.isPointer()) {
			try {
				in = messageReceiver.retrieveAttachment(attachment.asPointer(), buffer, progressListener);
			} catch (InvalidMessageException e) {
				fireSecurityException(sender, e);
			}
		} else {
			in = attachment.asStream().getInputStream();
		}
		Files.copy(in, file.toPath(), StandardCopyOption.REPLACE_EXISTING);
		
		buffer.delete();
		return file;
	}
	
	/**
	 * Convenience method to delete attachments
	 * @param id
	 */
	public void deleteAttachment(String id) {
		File attachment = Paths.get(ATTACHMENTS_PATH, id).toFile();
		if(attachment.exists()) {
			attachment.delete();
		}
	}
	
	/**
	 * Convenience method to get a file handle for an already saved attachment.
	 * @param id
	 * @return the file or null if no corresponding file is cached
	 */
	public File getAttachment(String id) {
		File attachment = Paths.get(ATTACHMENTS_PATH, id).toFile();
		if(attachment.exists()) {
			return attachment;
		} else {
			return null;
		}
	}
	
	/**
	 * Returns the data store where the contacts and groups are stored.<br>
	 * There are two stores (key store (private) and data store), both saved in {@code STORE_PATH}. Both stores are managed by the library,
	 * so you should only use this store for reading it. If you have to change something manually, call {@code save()}
	 * afterwards.
	 * @return the data store
	 */
	public DataStore getDataStore() {
		return store.getDataStore();
	}
	
	/**
	 * Leaves the group.<br><br>
	 * <b>Hack:</b> You can use a custom crafted group. This can be useful to leave a group where you lost the store for.
	 * @param group
	 * @throws IOException 
	 */
	public void leaveGroup(Group group) throws IOException {
		SignalServiceDataMessage message = SignalServiceDataMessage.newBuilder()
				.withTimestamp(System.currentTimeMillis())
				.asGroupMessage(SignalServiceGroup.newBuilder(Type.QUIT)
						.withId(group.getId().getId())
						.build())
				.build();
		sendMessage(group.getMembers(), message);
	}
	
}
