/**
 * CS255 project 2
 */
/**
 * CS255 Project 2
 */

package mitm;

import java.net.*;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.*;
import java.util.regex.*;

// You need to add code to do the following
// 1) use SSL sockets instead of the plain sockets provided
// 2) check user authentication
// 3) perform the given administration command

class MITMAdminServer implements Runnable
{
	private ServerSocket m_serverSocket;
	private Socket m_socket = null;
	private HTTPSProxyEngine m_engine;
	private PasswordManager m_passwordManager;

	public MITMAdminServer( String localHost, int adminPort, HTTPSProxyEngine engine ) throws IOException {
//		MITMPlainSocketFactory socketFactory = new MITMPlainSocketFactory();
		MITMSSLSocketFactory socketFactory;
		try {
			socketFactory = new MITMSSLSocketFactory();
			m_serverSocket = socketFactory.createServerSocket( localHost, adminPort, 0 );
			m_engine = engine;
		} catch (GeneralSecurityException e) {
//			e.printStackTrace();
		}
		
		// create a PasswordManager to authenticate passwords
		final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
		final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
		final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

		final KeyStore keyStore;
		try {
			if (keyStoreFile != null) {
				keyStore = KeyStore.getInstance(keyStoreType);
				keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);
			} else {
				keyStore = null;
			}
			PrivateKey privateKey = (PrivateKey) keyStore.getKey(System.getProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY), new String("password").toCharArray());
			m_passwordManager = new PasswordManager(System.getProperty(JSSEConstants.PASSWORD_FILE_PROPERTY), privateKey);
		} catch(Exception e) {
			e.printStackTrace();
		}
	}

	public void run() {
		System.out.println("Admin server initialized, listening on port " + m_serverSocket.getLocalPort());
		while( true ) {
			try {
				m_socket = m_serverSocket.accept();

				byte[] buffer = new byte[40960];

				Pattern userPwdPattern =
						Pattern.compile("username:(\\S+)\\s+password:(\\S+)\\s+command:(\\S+)\\sCN:(\\S*)\\s");

				BufferedInputStream in =
						new BufferedInputStream(m_socket.getInputStream(),
								buffer.length);

				// Read a buffer full.
				int bytesRead = in.read(buffer);

				String line = bytesRead > 0 ? new String(buffer, 0, bytesRead) : "";

				Matcher userPwdMatcher = userPwdPattern.matcher(line);

				// parse username and pwd
				if (userPwdMatcher.find()) {
					String userName = userPwdMatcher.group(1);
					String password = userPwdMatcher.group(2);

					// DONETODO authenticate
					// if authenticated, do the command
//					boolean authenticated = true;
					boolean authenticated = m_passwordManager.checkPassword(userName, password);
					if( authenticated ) {
						String command = userPwdMatcher.group(3);
						String commonName = userPwdMatcher.group(4);

						doCommand( command );
					} else {
						PrintWriter writer = new PrintWriter(m_socket.getOutputStream());
						writer.println("Wrong username or password.");
						writer.flush();
						m_socket.close();
					}
				}	
			}
			catch( InterruptedIOException e ) {
			}
			catch( Exception e ) {
				e.printStackTrace();
			}
		}
	}
	
    // DONETODO implement the commands
    private void doCommand( String cmd ) throws IOException {
    	PrintWriter writer = new PrintWriter(m_socket.getOutputStream());
    	if(cmd.equals("shutdown")){
    		writer.println("Shutting down proxy server.");
    		// TODO doesn't output anything when shutdown!
    		writer.flush();
    		m_engine.shutdown();
    	} else if(cmd.equals("stats")) {
    		int numRequests = m_engine.getNumRequests();
    		writer.println("Number of requests was: " + numRequests);
    	} else {
    		writer.println("Please submit a valid command: \"shutdown\" or \"stats\"");
    	}
    	writer.flush();
    	m_socket.close();
	
    }

}