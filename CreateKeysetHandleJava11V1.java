package createKeysetTest;

// the programm tests for a serious warning with google tink aes gcm encrytion/decryption setup
// used libraries: google tink & protobuf
// jre: java 8 update 191 x64
// jre: java 11 0 1 x64
// tink: tink-1.2.1.jar http://central.maven.org/maven2/com/google/crypto/tink/tink/1.2.1/tink-1.2.1.jar
// protobuf: protobuf-java-3.6.1.jar http://central.maven.org/maven2/com/google/protobuf/protobuf-java/3.6.1/protobuf-java-3.6.1.jar
// environment: microsoft windows 10 build 1809 x64, 8 gb ram, ssd
// source: https://github.com/java-crypto/tink/EncryptionGcmJreTinkBcV3.java
// author: michael fehr, http://javacrypto.bplaced.net

import java.io.IOException;
import java.security.GeneralSecurityException;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import com.google.crypto.tink.config.TinkConfig;

public class CreateKeysetHandleJava11V1 {

	public static void main(String[] args) throws GeneralSecurityException, IOException {
		System.out.println("Create Google Tink KeysetHandle with Java 11");
		TinkConfig.register();
		// create keyset
		KeysetHandle keysetHandle = KeysetHandle.generateNew(AeadKeyTemplates.AES128_GCM);
	}
}
