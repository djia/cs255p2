package mitm;

import iaik.x509.X509Certificate;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Formatter;

import javax.crypto.Cipher;

public class PasswordUtil {
	
	public static byte[] encrypt(byte[] text, PublicKey key) throws Exception {
		int bufferLen = 100;
		ByteBuffer bb = ByteBuffer.wrap(text);
		bb.rewind();
		byte[] output = new byte[65536];
		int bytesParsed = 0;
		
		while (bb.remaining() > 0) {
			int numRemaining = bb.remaining();
			bufferLen = (numRemaining >=100) ? 100 : numRemaining;
			byte[] out = new byte[bufferLen];
			bb.get(out);
			byte[] finishedOut = encryptOnce(out, key);
			for(int i = 0; i < finishedOut.length; i++) {
				output[bytesParsed + i] = finishedOut[i];
			}
			bytesParsed += finishedOut.length;
		}
		return output;
	}
	
	/**
	 * reads from a byte array and puts the results in a file
	 * @param text byte array input
	 * @param key the public key
	 * @param outputFileName the name of the output file
	 * @throws Exception
	 */
	public static void encryptAndWrite(byte[] text, PublicKey key, String outputFileName) throws Exception {
		int bufferLen = 100;
		ByteBuffer bb = ByteBuffer.wrap(text);
		bb.rewind();
		
		FileOutputStream fos = new FileOutputStream(outputFileName);
		
		while (bb.remaining() > 0) {
			int numRemaining = bb.remaining();
			bufferLen = (numRemaining >=100) ? 100 : numRemaining;
			byte[] out = new byte[bufferLen];
			bb.get(out);
			byte[] finishedOut = encryptOnce(out, key);
			fos.write(finishedOut);
		}
		fos.flush();
		fos.close();
	}
	
	private static byte[] encryptOnce(byte[] text, PublicKey key) throws Exception {
		byte[] cipherText = null;
		// get an RSA cipher object and print the provider
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

		// encrypt the plaintext using the public key
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipherText = cipher.doFinal(text);
		return cipherText;
	}
	
	/**
	 * decrypts the contents of a file with the private key
	 * @param inputFileName the name o the file to decrypt
	 * @param key the private key
	 * @return
	 * @throws Exception
	 */
	public static byte[] readAndDecrypt(String inputFileName, PrivateKey key) throws Exception {
		int bufferLen = 128;
		InputStream inputReader = new FileInputStream(inputFileName);
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		byte[] buf = new byte[128];
		ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
		int bufl;
		while ( (bufl = inputReader.read(buf)) != -1) {
			byte[] encText = null;
			encText = decryptOnce(copyBytes(buf,bufl), key);
			byteOutputStream.write(encText);
		}
		
		return byteOutputStream.toByteArray();
	}
	
	private static byte[] decryptOnce(byte[] text, PrivateKey key) throws Exception {
		byte[] dectyptedText = null;
		// decrypt the text using the private key
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		dectyptedText = cipher.doFinal(text);
		return dectyptedText;
	}
	
	public static void encryptDecryptFile(String srcFileName, String destFileName, Key key, int cipherMode) throws Exception {
		OutputStream outputWriter = null;
		InputStream inputReader = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			String textLine = null;
			byte[] buf = cipherMode == Cipher.ENCRYPT_MODE? new byte[100] : new byte[128];
			int bufl;
			// init the Cipher object for Encryption…
			cipher.init(cipherMode, key);
			// start FileIO
			outputWriter = new FileOutputStream(destFileName);
			inputReader = new FileInputStream(srcFileName);
			String result = "";
			while ( (bufl = inputReader.read(buf)) != -1) {
				byte[] encText = null;
				if (cipherMode == Cipher.ENCRYPT_MODE) {
					encText = encrypt(copyBytes(buf,bufl),(PublicKey)key);
				} else {
					encText = decryptOnce(copyBytes(buf,bufl),(PrivateKey)key);
				}
				outputWriter.write(encText);
//				result += new String(encText);
			}
			System.out.println(result);
			outputWriter.flush();
		} finally {
			try {
				if (outputWriter != null){
					outputWriter.close();
				}
				if (inputReader != null){
					inputReader.close();
				}
			} catch (Exception e) {}
		}
	}
	
	public static byte[] copyBytes(byte[] arr, int length) {
	  byte[] newArr = null;
	  if (arr.length == length) {
	    newArr = arr;
	  } else {
	    newArr = new byte[length];
	    for (int i = 0; i < length; i++) {
	      newArr[i] = (byte) arr[i];
	    }
	  }
	  return newArr;
	}
	
	
	public static byte[] SHAsum(byte[] toConvert) throws NoSuchAlgorithmException{
	    MessageDigest md = MessageDigest.getInstance("SHA-1");
	    return md.digest(toConvert);
	}
	
	/**
	 * converts a byte array to a string by first converting each byte to an integer and then casting to string
	 * @param bytes the bytes array
	 * @param separator the separator to put between each byte
	 * @return
	 */
	public static String bytesToString(byte[] bytes, String separator) {
		String output = "";
		for(int i = 0; i < bytes.length; i++) {
			if(i != 0) {
				output += separator;
			}
			output += "" + (int)bytes[i];
		}
		return output;
	}
	
	public static byte[] stringToBytes(String string, String separator) {
		String[] parts = string.split(separator);
		byte[] output = new byte[parts.length];
		for(int i = 0; i < parts.length; i++) {
			output[i] = (byte)Integer.parseInt(parts[i]);
		}
		return output;
	}
	
	
	public static byte[] concatBytes(byte[] A, byte[] B) {
		byte[] C= new byte[A.length+B.length];
		System.arraycopy(A, 0, C, 0, A.length);
		System.arraycopy(B, 0, C, A.length, B.length);
		
		return C;
	}
	
	
	
}
