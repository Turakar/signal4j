# signal4j
A facade to make using the libsignal-service easy

## Installation

You have to have the JCE Unlimited Strength Policy Files installed if you are using the Oracle JRE.

### Gradle
```gradle
repositories {
    mavenCentral()
}

dependencies {
    compile 'com.github.turakar:signal4j:1.0.0'
}
```
### Maven
```maven
<dependency>
  <groupId>com.github.turakar</groupId>
  <artifactId>signal4j</artifactId>
  <version>1.0.0</version>
</dependency>
```

## Usage
Central part of the library is the `SignalService` class.

### Storage
The library stores all your keys and metadata (not messages themself) inside the store `store.json`. The store is managed and saved on any changes by the library. To reset the state delete the store file. The saved contacts and groups are updated automatically on incoming messages.

### Register
You can register as primary or secondary (provisioned) device using the methods `startConnectAsPrimary()`, `finishConnectAsPrimary()`, `startConnectAsSecondary()`, `finishConnectAsSecondary()`. See the javadoc for further details on this. You only have to do this at install time. Do not do this again without deleting the store file.

### PreKeys
PreKeys are used for encryption and have to be generated prior to using them. Therefore you can use `checkPreKeys()` which has to be called regularly. 

### Sync
You can request a sync message (containing contacts, groups and blocked list) using `requestSync()`. This will populate the store file.

### Sending Messages
Messages are represented by `SignalServiceDataMessage`. You can either create them using the constructors or using the builder. Attachments should be sent as `SignalServiceAttachmentStream`. To send a message use `sendMessage()`.

### Receiving Messages
Receiving is done using `pull()` which is a blocking operation. Messages are processed using `ConversationListener` which has to be added prior to calling `pull()` using `addConversationListener()`. The `ConversationListener` receives all data messages through `onMessage()` (even the ones of another device of you) while associating `User` objects automatically to the sender's phone number. It additionally receives sync updates (those from `requestSync()` too) through `onContactUpdate()` and `onGroupUpdate()`. Using `onReadUpdate()` you can get read notifications from a different device of you. You cannot send read notifications yourself in the moment (WIP). Remember that read notifications are not transmitted to your contacts but only to the devices you use to manage notifications.
#### Downloading attachments
You can download attachments using `saveAttachment()`. The attachments are saved to the folder `attachments` and you get a `File` object pointing at it. There are convenience methods for getting a saved attachment (`getAttachment()`) and deleting a saved attachment (`deleteAttachment()`). The avatars of contacts and groups are downloaded automatically with the sync messages and therefore should be retrieved only using `getAttachment()`. Old avatars are automatically deleted once a new avatar arrives.
