package StreamingAead;

// programm measures the execution times for an aes gcm encrytion/decryption
// used libraries: jre, bouncycastle and google tink
// jre: java 8 update 191 x64
// bouncycastle: bcprov-jdk15on-160.jar http://central.maven.org/maven2/org/bouncycastle/bcprov-jdk15on/1.60/bcprov-jdk15on-1.60.jar
// tink: tink-1.2.1.jar http://central.maven.org/maven2/com/google/crypto/tink/tink/1.2.1/tink-1.2.1.jar
// protobuf: protobuf-java-3.6.1.jar http://central.maven.org/maven2/com/google/protobuf/protobuf-java/3.6.1/protobuf-java-3.6.1.jar
// environment: microsoft windows 10 build 1809 x64, 8 gb ram, ssd
// source: https://github.com/java-crypto/tink/EncryptionGcmJreTinkBc.java
// author: michael fehr, http://javacrypto.bplaced.net

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.StreamingAead;
import com.google.crypto.tink.config.TinkConfig;
import com.google.crypto.tink.streamingaead.StreamingAeadFactory;
import com.google.crypto.tink.streamingaead.StreamingAeadKeyTemplates;

public class EncryptionGcmJreTinkBc {

	// statics for jre and bc
	private static final int GCM_NONCE_LENGTH = 12;
	private static final int GCM_TAG_LENGTH = 16;

	public static void main(String[] args) throws IOException, GeneralSecurityException {
		System.out.println("Execution times for AES GCM with large files using JRE, TINK and BC");

		// setup the libraries
		Security.addProvider(new BouncyCastleProvider());
		TinkConfig.register();
		// key generation tink
		KeysetHandle keysetHandleGcm = KeysetHandle.generateNew(StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB);
		StreamingAead aead = StreamingAeadFactory.getPrimitive(keysetHandleGcm);
		byte[] aad = new byte[0];
		// password for jre and bc
		byte[] password = "12345678901234567890123456789012".getBytes("utf-8"); // 32 byte = 256 bit
		// time
		long startMilli = 0;
		long finishMilli = 0;
		long encryptionMilli = 0;
		long decryptionMilli = 0;
		// warmup vars
		String filenameWarmup = "E:\\warmup.dat"; // choose a destination
		String filenameWarmupEnc = filenameWarmup + ".enc";
		String filenameWarmupDec = filenameWarmup + ".dec";
		// filenames for real time measures
		String filenameBaseString = "E:\\t_"; // choose a destination
		String filenameEndingString = ".dat";
		String filenamePlain = "";
		long fileSize = 0;

		// aes gcm jre
		// warmup
		createFileWithDefinedLength(filenameWarmup, 1024);
		encryptWithGcmJre(filenameWarmup, filenameWarmupEnc, password);
		decryptWithGcmJre(filenameWarmupEnc, filenameWarmupDec, password);
		Files.deleteIfExists(new File(filenameWarmup).toPath());
		Files.deleteIfExists(new File(filenameWarmupEnc).toPath());
		Files.deleteIfExists(new File(filenameWarmupDec).toPath());

		System.out.println("\nGCM Encryption / Decryption with JRE");
		System.out.println("Round\tFilename\tEnc\tDec");
		for (int round = 1; round < 6; round++) {
			// create testfile
			filenamePlain = filenameBaseString + round + "mb" + filenameEndingString;
			fileSize = (round * 1 * 1024 * 1024);
			createFileWithDefinedLength(filenamePlain, fileSize);
			String filenameEnc = filenamePlain + ".enc";
			String filenameDec = filenamePlain + ".dec";
			// encryption
			startMilli = System.currentTimeMillis();
			encryptWithGcmJre(filenamePlain, filenameEnc, password);
			finishMilli = System.currentTimeMillis();
			encryptionMilli = finishMilli - startMilli;
			// decryption
			startMilli = System.currentTimeMillis();
			decryptWithGcmJre(filenameEnc, filenameDec, password);
			finishMilli = System.currentTimeMillis();
			decryptionMilli = finishMilli - startMilli;
			// output
			System.out.println(round + "\t" + filenamePlain + "\t" + encryptionMilli + "\t" + decryptionMilli);
			// delete testfiles
			Files.deleteIfExists(new File(filenamePlain).toPath());
			Files.deleteIfExists(new File(filenameEnc).toPath());
			Files.deleteIfExists(new File(filenameDec).toPath());
		}

		// aes gcm with google tink
		// warmup
		createFileWithDefinedLength(filenameWarmup, 1024);
		encryptWithGcmTink(aead, filenameWarmup, filenameWarmupEnc, aad);
		decryptWithGcmTink(aead, filenameWarmupEnc, filenameWarmupDec, aad);
		Files.deleteIfExists(new File(filenameWarmup).toPath());
		Files.deleteIfExists(new File(filenameWarmupEnc).toPath());
		Files.deleteIfExists(new File(filenameWarmupDec).toPath());

		System.out.println("\nGCM Encryption / Decryption with TINK");
		System.out.println("Round\tFilename\tEnc\tDec");
		for (int round = 1; round < 6; round++) {
			// create testfile
			filenamePlain = filenameBaseString + round + "mb" + filenameEndingString;
			fileSize = (round * 1 * 1024 * 1024);
			createFileWithDefinedLength(filenamePlain, fileSize);
			String filenameEnc = filenamePlain + ".enc";
			String filenameDec = filenamePlain + ".dec";
			// encryption
			startMilli = System.currentTimeMillis();
			encryptWithGcmJre(filenamePlain, filenameEnc, password);
			finishMilli = System.currentTimeMillis();
			encryptionMilli = finishMilli - startMilli;
			// decryption
			startMilli = System.currentTimeMillis();
			decryptWithGcmJre(filenameEnc, filenameDec, password);
			finishMilli = System.currentTimeMillis();
			decryptionMilli = finishMilli - startMilli;
			// output
			System.out.println(round + "\t" + filenamePlain + "\t" + encryptionMilli + "\t" + decryptionMilli);
			// delete testfiles
			Files.deleteIfExists(new File(filenamePlain).toPath());
			Files.deleteIfExists(new File(filenameEnc).toPath());
			Files.deleteIfExists(new File(filenameDec).toPath());
		}

		// aes gcm bc
		// warmup
		createFileWithDefinedLength(filenameWarmup, 1024);
		encryptWithGcmBc(filenameWarmup, filenameWarmupEnc, password);
		decryptWithGcmBc(filenameWarmupEnc, filenameWarmupDec, password);
		Files.deleteIfExists(new File(filenameWarmup).toPath());
		Files.deleteIfExists(new File(filenameWarmupEnc).toPath());
		Files.deleteIfExists(new File(filenameWarmupDec).toPath());

		System.out.println("\nGCM Encryption / Decryption with BC");
		System.out.println("Round\tFilename\tEnc\tDec");
		for (int round = 1; round < 6; round++) {
			// create testfile
			filenamePlain = filenameBaseString + round + "mb" + filenameEndingString;
			fileSize = (round * 1 * 1024 * 1024);
			createFileWithDefinedLength(filenamePlain, fileSize);
			String filenameEnc = filenamePlain + ".enc";
			String filenameDec = filenamePlain + ".dec";
			// encryption
			startMilli = System.currentTimeMillis();
			encryptWithGcmBc(filenamePlain, filenameEnc, password);
			finishMilli = System.currentTimeMillis();
			encryptionMilli = finishMilli - startMilli;
			// decryption
			startMilli = System.currentTimeMillis();
			decryptWithGcmBc(filenameEnc, filenameDec, password);
			finishMilli = System.currentTimeMillis();
			decryptionMilli = finishMilli - startMilli;
			// output
			System.out.println(round + "\t" + filenamePlain + "\t" + encryptionMilli + "\t" + decryptionMilli);
			// delete testfiles
			Files.deleteIfExists(new File(filenamePlain).toPath());
			Files.deleteIfExists(new File(filenameEnc).toPath());
			Files.deleteIfExists(new File(filenameDec).toPath());
		}
		System.out.println("\nExecution times for AES GCM with large files using JRE, TINK and BC ended");
	}

	public static void encryptWithGcmJre(String filenamePlain, String filenameEnc, byte[] key) throws IOException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		InputStream is = new BufferedInputStream(new FileInputStream(filenamePlain));
		OutputStream os = new BufferedOutputStream(new FileOutputStream(filenameEnc));
		SecureRandom r = new SecureRandom();
		byte[] nonce = new byte[GCM_NONCE_LENGTH];
		r.nextBytes(nonce);
		os.write(nonce);
		os.flush();
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
		os = new CipherOutputStream(os, cipher);
		byte[] buf = new byte[1024];
		int numRead = 0;
		while ((numRead = is.read(buf)) >= 0) {
			os.write(buf, 0, numRead);
		}
		is.close();
		os.close();
	}

	public static void decryptWithGcmJre(String filenameEnc, String filenameDec, byte[] key) throws IOException,
			NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		InputStream is = new BufferedInputStream(new FileInputStream(filenameEnc));
		OutputStream os = new BufferedOutputStream(new FileOutputStream(filenameDec));
		byte[] nonce = new byte[GCM_NONCE_LENGTH];
		is.read(nonce);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
		cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
		is = new CipherInputStream(is, cipher);
		byte[] buf = new byte[1024];
		int numRead = 0;
		while ((numRead = is.read(buf)) >= 0) {
			os.write(buf, 0, numRead);
		}
		is.close();
		os.close();
	}

	public static void encryptWithGcmTink(StreamingAead aead, String filenamePlain, String filenameEnc, byte[] aad)
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

	public static void decryptWithGcmTink(StreamingAead aead, String filenameEnc, String filenameDec, byte[] aad)
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

	public static void encryptWithGcmBc(String filenamePlain, String filenameEnc, byte[] key)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException {
		InputStream is = new BufferedInputStream(new FileInputStream(filenamePlain));
		OutputStream os = new BufferedOutputStream(new FileOutputStream(filenameEnc));
		SecureRandom r = new SecureRandom();
		byte[] nonce = new byte[GCM_NONCE_LENGTH];
		r.nextBytes(nonce);
		os.write(nonce);
		os.flush();
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
		os = new CipherOutputStream(os, cipher);
		byte[] buf = new byte[1024];
		int numRead = 0;
		while ((numRead = is.read(buf)) >= 0) {
			os.write(buf, 0, numRead);
		}
		is.close();
		os.close();
	}

	public static void decryptWithGcmBc(String filenameEnc, String filenameDec, byte[] key)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException {
		InputStream is = new BufferedInputStream(new FileInputStream(filenameEnc));
		OutputStream os = new BufferedOutputStream(new FileOutputStream(filenameDec));
		byte[] nonce = new byte[GCM_NONCE_LENGTH];
		is.read(nonce);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
		cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
		is = new CipherInputStream(is, cipher);
		byte[] buf = new byte[1024];
		int numRead = 0;
		while ((numRead = is.read(buf)) >= 0) {
			os.write(buf, 0, numRead);
		}
		is.close();
		os.close();
	}

	private static void createFileWithDefinedLength(String filenameString, long sizeLong) throws IOException {
		RandomAccessFile raf = new RandomAccessFile(filenameString, "rw");
		try {
			raf.setLength(sizeLong);
		} finally {
			raf.close();
		}
	}

}