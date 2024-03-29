package mitm;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;

public class PasswordManager {
	
	private String m_encryptedPwdFileName;
	private KeyStore m_keyStore;
	private PrivateKey m_privateKey;
	
	/**
	 * for testing
	 */
//	public static void main(String[] args) {
//		String encryptedPwdFileName = "pwd.txt";
//		
////		System.setProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "password");
////		System.setProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "mykey");
//		
//		try {
////			keyStore = KeyStore.getInstance(System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks"));
////			keyStore.load(new FileInputStream("ks"), new String("password").toCharArray());
////			PrivateKey privateKey = (PrivateKey) keyStore.getKey(System.getProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY), System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY).toCharArray());
//			
//			KeyStore keyStore = KeyStore.getInstance(System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks"));
//			keyStore.load(new FileInputStream("ks"), new String("password").toCharArray());
//			PrivateKey privateKey = (PrivateKey) keyStore.getKey("mykey", new String("password").toCharArray());
//			
//			PasswordManager passwordManager = new PasswordManager(encryptedPwdFileName, privateKey);
//			passwordManager.checkPassword("dillon", "password2");
//		} catch (Exception e) {
//			e.printStackTrace();
//		}
//	}
	
	/**
	 * given an encrypted password file name, creates a PasswordManager object
	 * @param pwdFileName the name of the encrypted password file
	 * @param keyStore the keystore object used to decrypt the password file
	 */
	public PasswordManager(String encryptedPwdFileName, PrivateKey privateKey) {
		this.m_encryptedPwdFileName = encryptedPwdFileName;
		this.m_privateKey = privateKey;
	}
	
	/**
	 * given a plaintext username and password, checks whether it's in the encrypted password file
	 * @param username
	 * @param password
	 * @return whether username / password combo matches
	 */
	public boolean checkPassword(String username, String password) {
		boolean passwordChecked = false;
		
		// decrypt the file
		
		try {
			// get the file data as a string and loop through each line
			byte[] byteArr = PasswordUtil.readAndDecrypt(m_encryptedPwdFileName, m_privateKey);
			String contents = new String(byteArr);
			String[] parts1 = contents.split("::");
			// for each, check if username / password combo exists
			for(int i = 0; i < parts1.length; i++) {
				String part1 = parts1[i];
				if(part1.equals("")) {
					continue;
				}
				String[] parts2 = part1.split(":");
				if(!parts2[0].equals(username)) {
					continue;
				}
				// check that the salt + password under sha1 is the same
				byte[] salt = PasswordUtil.stringToBytes(parts2[1], ",");
				byte[] saltEncrypted = PasswordUtil.stringToBytes(parts2[2], ",");
				
				byte[] saltPassword = PasswordUtil.concatBytes(salt, password.getBytes());
				byte[] testSaltEncrypted = PasswordUtil.SHAsum(saltPassword);
				
				if(Arrays.equals(saltEncrypted, testSaltEncrypted)) {
					passwordChecked = true;
					break;
				}
			}
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
		}
		
		
		return passwordChecked;
	}
	
	
	public byte[] getSaltForUsername(String username) {
		try {
			// get the file data as a string and loop through each line
			byte[] byteArr = PasswordUtil.readAndDecrypt(m_encryptedPwdFileName, m_privateKey);
			String contents = new String(byteArr);
			String[] parts1 = contents.split("::");
			// for each, check if username / password combo exists
			for(int i = 0; i < parts1.length; i++) {
				String part1 = parts1[i];
				if(part1.equals("")) {
					continue;
				}
				String[] parts2 = part1.split(":");
				if(!parts2[0].equals(username)) {
					continue;
				}
				byte[] salt = PasswordUtil.stringToBytes(parts2[1], ",");
				return salt;
			}
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
		}
		return null;
	}
	
	public byte[] getSaltPasswordEncryptedForUsername(String username) {
		try {
			// get the file data as a string and loop through each line
			byte[] byteArr = PasswordUtil.readAndDecrypt(m_encryptedPwdFileName, m_privateKey);
			String contents = new String(byteArr);
			String[] parts1 = contents.split("::");
			// for each, check if username / password combo exists
			for(int i = 0; i < parts1.length; i++) {
				String part1 = parts1[i];
				if(part1.equals("")) {
					continue;
				}
				String[] parts2 = part1.split(":");
				if(!parts2[0].equals(username)) {
					continue;
				}
				byte[] saltEncrypted = PasswordUtil.stringToBytes(parts2[2], ",");
				return saltEncrypted;
			}
		} catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
		}
		return null;
	}
	
	
	
	
	
	
	
}
