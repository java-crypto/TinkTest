package StreamingAead;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;

// basis: StreamingTestUtil.java von Tink
// dieses programm funktioniert, nachteil: channels !

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.streamingaead.StreamingAeadFactory;
import com.google.crypto.tink.streamingaead.StreamingAeadKeyTemplates;

public class StreamingEncryptionVonTestV3 {

	public static void main(String[] args) throws Exception {
		System.out.println("StreamingEncryptionVonTest");

		TinkConfig.register();

		KeysetHandle keysetHandleGcm = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES128_GCM_HKDF_4KB);
		StreamingAead aead = StreamingAeadFactory.getPrimitive(keysetHandleGcm);

		// byte[] aad = TestUtil.hexDecode("aabbccddeeff");
		//byte[] aad = "aad-Daten".getBytes("utf-8");
		byte[] aad = new byte[0];
		// byte[] pt = generatePlaintext(plaintextSize);
		byte[] plaintext = "1234567890".getBytes("utf-8");
		String outputfileEncString = "StreamingEncryptionVonTest.enc";
		File outputfileEnc = new File(outputfileEncString);
		String outputfileDecString = "StreamingEncryptionVonTest.dec";

		fileEncryptionWithStream(aead, outputfileEnc, plaintext, aad);
		System.out.println("Verschlüsselte Datei erzeugt:" + outputfileEncString);
		fileDecryptionWithStream(aead, outputfileDecString, outputfileEnc, aad);
		System.out.println("Entschlüsselte Datei erzeugt:" + outputfileDecString);

		/*
		String filenamePlain = "S:\\test1026.txt";
		String filenameEnc = "S:\\test1026enc.txt";
		String filenameDec = "S:\\test1026dec.txt";
		*/
		String filenamePlain = "S:\\11mb.exe";
		String filenameEnc = "S:\\test1026enc.txt";
		String filenameDec = "S:\\11mbdec.exe";
		
		System.out.println("\nStream:" + filenamePlain + " Enc:" + filenameEnc + " Dec:" + filenameDec);
		fileEncryptionWithStreamComplete(aead, filenamePlain, filenameEnc, aad);
		fileDecryptionWithStreamComplete(aead, filenameEnc, filenameDec, aad);

		System.out.println("StreamingEncryptionVonTest Ende");
	}

	private static void fileEncryptionWithStream(StreamingAead aead, File outputfileEnc, byte[] plaintext, byte[] aad)
			throws GeneralSecurityException, IOException {
		// dateiausgabe
		FileOutputStream ctStream = new FileOutputStream(outputfileEnc);
		WritableByteChannel channel = Channels.newChannel(ctStream);
		WritableByteChannel encChannel = aead.newEncryptingChannel(channel, aad);
		OutputStream encStream = Channels.newOutputStream(encChannel);
		// Writing single bytes appears to be the most troubling case.
		for (int i = 0; i < plaintext.length; i++) {
			encStream.write(plaintext[i]);
		}
		encStream.close();
	}

	public static void fileEncryptionWithStreamComplete(StreamingAead aead, String filenamePlain, String filenameEnc,
			byte[] aad)
			throws GeneralSecurityException, IOException {
		InputStream is = new BufferedInputStream(new FileInputStream(filenamePlain));
		BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filenameEnc));
		OutputStream os = aead.newEncryptingStream(bos, aad);
		byte[] buf = new byte[1024];
		int numRead = 0;
		while ((numRead = is.read(buf)) >= 0) {
			os.write(buf, 0, numRead);
		}
		is.close();
		os.close();
	}

	public static void fileDecryptionWithStreamComplete(StreamingAead aead, String filenameEnc, String filenameDec,
			byte[] aad)
			throws GeneralSecurityException, IOException {
		BufferedInputStream bis = new BufferedInputStream(new FileInputStream(filenameEnc));
		OutputStream os = new BufferedOutputStream(new FileOutputStream(filenameDec));
		InputStream is = aead.newDecryptingStream(bis, aad);
		byte[] buf = new byte[1024];
		int numRead = 0;
		while ((numRead = is.read(buf)) >= 0) {
			os.write(buf, 0, numRead);
		}
		is.close();
		os.close();
	}

	private static void fileDecryptionWithStream(StreamingAead aead, String outputfileDecString, File inputfileEnc,
			byte[] aad) throws GeneralSecurityException, IOException {
		FileInputStream inpStream = new FileInputStream(inputfileEnc);
		ReadableByteChannel inpChannel = Channels.newChannel(inpStream);
		ReadableByteChannel decryptedChannel = aead.newDecryptingChannel(inpChannel, aad);
		InputStream decrypted = Channels.newInputStream(decryptedChannel);
		// dateiausgabe
		FileOutputStream fos = new FileOutputStream(outputfileDecString);
		DataOutputStream dos = new DataOutputStream(fos);
		int read;
		while (true) {
			read = decrypted.read();
			if (read == -1) {
				break;
			}
			dos.write(read);
		}
		dos.close();
	}

}
