package mitm;

import iaik.x509.X509Certificate;

import java.io.BufferedReader;
import mitm.PasswordUtil;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;

public class PasswordEncrypter {
	
	private String m_plainPwdFileName;
	private String m_encryptedPwdFileName;
	private KeyStore m_keyStore;
	private PublicKey m_publicKey;
	private PrivateKey m_privateKey;
	
	private HashMap<String, String> m_usernameToPassword;
	private HashMap<String, String> m_usernameToSalt;
	
	public static void main(String[] args) {
		PasswordEncrypter pwdManager = new PasswordEncrypter(args);
		pwdManager.encryptPwdFile();
	}

	private Error printUsage() {
		System.err.println(
				"\n" +
						"Usage: " +
						"\n java " + PasswordEncrypter.class + " <options>" +
						"\n" +
						"\n Where options can include:" +
						"\n" +
						"\n   [-plainPasswordFile <file> ] Plaintext Password file" +
						"\n   [-keyStore <file>]           Key store details for" +
						"\n   [-keyStorePassword <pass>]   certificates. Equivalent to" +
						"\n   [-keyStoreAlias <alias>]     Default is keytool default of 'mykey'" +
						"\n   [-outputFile <filename>]     Encrypted Password file output default to 'pwd.txt'" +
						"\n" +
						"\n -outputFile specifies the file that the encrypted password data will go." +
						"\n"
				);

		System.exit(1);
		return null;
	}
	
	/**
	 * used for the commandline utility for encrypting a password file
	 * @param args
	 */
	public PasswordEncrypter(String[] args) {
		// Default values.
		System.setProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY, "mykey");
		this.m_encryptedPwdFileName = "pwd.txt";

		try {
			for (int i=0; i<args.length; i++)
			{
				if( args[i].equals("-plainPasswordFile")) {
					this.m_plainPwdFileName = args[++i];
				} else if (args[i].equals("-keyStore")) {
					System.setProperty(JSSEConstants.KEYSTORE_PROPERTY, args[++i]);
				} else if (args[i].equals("-keyStorePassword")) {
					System.setProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, args[++i]);
				} else if (args[i].equals("-keyStoreAlias")) {
					System.setProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY, args[++i]);
				} else if (args[i].equals("-outputFile")) {
					this.m_encryptedPwdFileName = args[++i];
				} else {
					throw printUsage();
				}
			}
		}
		catch (Exception e) {
			throw printUsage();
		}
		
		// get the keystore, publicKey and privateKey
		try {
			m_keyStore = KeyStore.getInstance(System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks"));
			m_keyStore.load(new FileInputStream(System.getProperty(JSSEConstants.KEYSTORE_PROPERTY)), System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY).toCharArray());
			m_privateKey = (PrivateKey) m_keyStore.getKey(System.getProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY), System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY).toCharArray());
			
			
			java.security.cert.X509Certificate javaCert = (java.security.cert.X509Certificate)m_keyStore.getCertificate(System.getProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY));
			byte[] javaCertBytes = javaCert.getEncoded();
			
			X509Certificate newCert = new X509Certificate(javaCertBytes);
			m_publicKey = (PublicKey)newCert.getPublicKey();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	
	/**
	 * used with the commandline utility to encrypt a
	 * password file and output the results in -outputFile
	 * hashes each password with a salt first, then
	 * encrypts the entire file with the public key
	 * from the keystore
	 */
	private void encryptPwdFile() {
//		byte[] outputFileData = new byte[65536];
		ArrayList<Byte> outputFileData = new ArrayList<Byte>();
		SecureRandom secureRandom = new SecureRandom();
		String newLineCharacter = "::";
		
		int bytesParsed = 0;
		
		// open the plaintext password file and map the username to password and username to salt
		try{
			FileInputStream fstream = new FileInputStream(this.m_plainPwdFileName);
			DataInputStream in = new DataInputStream(fstream);
			BufferedReader br = new BufferedReader(new InputStreamReader(in));
			String strLine;
			//Read File Line By Line
			while ((strLine = br.readLine()) != null)   {
				// Print the content on the console
				String[] parts = strLine.split(":");
				byte[] username = parts[0].getBytes();
				byte[] password = parts[1].getBytes();
				byte[] salt = new byte[20];
				secureRandom.nextBytes(salt);
				// we encrypt salt + password
				byte[] saltPassword = concatBytes(salt, password);
				byte[] saltEncrypted = SHAsum(saltPassword);
				// add the salt to the front of it
				saltEncrypted = concatBytes(concatBytes(salt, new String(":").getBytes()), saltEncrypted);
				byte[] newLine = concatBytes(concatBytes(username, new String(":").getBytes()), saltEncrypted);
				newLine = concatBytes(newLine, newLineCharacter.getBytes());
				for(int i = 0; i < newLine.length; i++) {
//					outputFileData[bytesParsed + i] = newLine[i];
					outputFileData.add(newLine[i]);
				}
//				System.out.println(outputFileData);
//				outputFileData
				bytesParsed += newLine.length;
			}
			//Close the input stream
			in.close();
			
			//finally encrypt it with RSA from our keystore
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream out = new DataOutputStream(baos);
			for (byte element : outputFileData) {
			    out.write(element);
			}
			byte[] outputFileDataBytes = baos.toByteArray();
//			byte[] encryptedOutputFileData = PasswordUtil.encrypt(outputFileDataBytes, m_publicKey);
			
			// write it to the output file
			try{
				FileOutputStream fos = new FileOutputStream(this.m_encryptedPwdFileName);
//				fos.write(encryptedOutputFileData);
				fos.write(outputFileDataBytes);
				fos.close();
			} catch (Exception e){//Catch exception if any
				System.err.println("Error: " + e.getMessage());
			}
			
		} catch (Exception e){//Catch exception if any
			System.err.println("Error: " + e.getMessage());
		}
		
	}
	
	
	public static byte[] SHAsum(byte[] toConvert) throws NoSuchAlgorithmException{
	    MessageDigest md = MessageDigest.getInstance("SHA-1");
	    return md.digest(toConvert);
	}
	
	public static byte[] concatBytes(byte[] A, byte[] B) {
		byte[] C= new byte[A.length+B.length];
		System.arraycopy(A, 0, C, 0, A.length);
		System.arraycopy(B, 0, C, A.length, B.length);
		
		return C;
	}
	
	
}
