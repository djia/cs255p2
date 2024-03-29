//Based on SnifferSSLSocketFactory.java from The Grinder distribution.
// The Grinder distribution is available at http://grinder.sourceforge.net/

package mitm;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
//import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;

import javax.net.ServerSocketFactory;
import javax.net.SocketFactory;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.x500.X500Principal;

import iaik.asn1.structures.AlgorithmID;
import iaik.x509.X509Certificate;


/**
 * MITMSSLSocketFactory is used to create SSL sockets.
 *
 * This is needed because the javax.net.ssl socket factory classes don't
 * allow creation of factories with custom parameters.
 *
 */
public final class MITMSSLSocketFactory implements MITMSocketFactory
{
	final ServerSocketFactory m_serverSocketFactory;
	final SocketFactory m_clientSocketFactory;
	final SSLContext m_sslContext;

	public KeyStore ks = null;

	/*
	 *
	 * We can't install our own TrustManagerFactory without messing
	 * with the security properties file. Hence we create our own
	 * SSLContext and initialise it. Passing null as the keystore
	 * parameter to SSLContext.init() results in a empty keystore
	 * being used, as does passing the key manager array obtain from
	 * keyManagerFactory.getInstance().getKeyManagers(). To pick up
	 * the "default" keystore system properties, we have to read them
	 * explicitly. UGLY, but necessary so we understand the expected
	 * properties.
	 *
	 */

	/**
	 * This constructor will create an SSL server socket factory
	 * that is initialized with a fixed CA certificate
	 */
	public MITMSSLSocketFactory()
			throws IOException,GeneralSecurityException
	{
		m_sslContext = SSLContext.getInstance("SSL");
	
		final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

		final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
		final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
		final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

		final KeyStore keyStore;

		if (keyStoreFile != null) {
			keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

			this.ks = keyStore;
		} else {
			keyStore = null;
		}

		keyManagerFactory.init(keyStore, keyStorePassword);

		m_sslContext.init(keyManagerFactory.getKeyManagers(), new TrustManager[] { new TrustEveryone() }, null);

		m_clientSocketFactory = m_sslContext.getSocketFactory();
		m_serverSocketFactory = m_sslContext.getServerSocketFactory(); 
	}

	/**
	 * This constructor will create an SSL server socket factory
	 * that is initialized with a dynamically generated server certificate
	 * that contains the specified common name.
	 */
//	public MITMSSLSocketFactory(String remoteCN, BigInteger serialNumber)
	public MITMSSLSocketFactory(byte[] certificateBytes)
			throws IOException,GeneralSecurityException, Exception
	{
		// DONETODO: replace this with code to generate a new
		// server certificate with common name remoteCN
		
//		this();
		
		m_sslContext = SSLContext.getInstance("SSL");

		final KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

		final String keyStoreFile = System.getProperty(JSSEConstants.KEYSTORE_PROPERTY);
		final char[] keyStorePassword = System.getProperty(JSSEConstants.KEYSTORE_PASSWORD_PROPERTY, "").toCharArray();
		final String keyStoreType = System.getProperty(JSSEConstants.KEYSTORE_TYPE_PROPERTY, "jks");

		final KeyStore keyStore;

		if (keyStoreFile != null) {
			keyStore = KeyStore.getInstance(keyStoreType);
			keyStore.load(new FileInputStream(keyStoreFile), keyStorePassword);

			this.ks = keyStore;
		} else {
			keyStore = null;
		}
		

		X509Certificate cert = new X509Certificate(certificateBytes);
		PrivateKey myKey = (PrivateKey) keyStore.getKey(System.getProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY), new String("password").toCharArray());
		
		// get the old certificate
		java.security.cert.X509Certificate oldJavaCert = (java.security.cert.X509Certificate)keyStore.getCertificate(System.getProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY));
		byte[] oldJavaCertBytes = oldJavaCert.getEncoded();
		
		// put the subjectDN from the remote certificate to the old certificate and sign it
		X509Certificate oldCert = new X509Certificate(oldJavaCertBytes);
		Principal certSubject = cert.getSubjectDN();
		Principal cerIssuer = cert.getIssuerDN();
		BigInteger serialNumber = cert.getSerialNumber();
		oldCert.setSubjectDN(certSubject);
		oldCert.setSerialNumber(serialNumber);
		oldCert.sign(AlgorithmID.sha1WithRSAEncryption, myKey);
		
		X509Certificate[] certChain = {oldCert};
		
		keyStore.setKeyEntry(System.getProperty(JSSEConstants.KEYSTORE_ALIAS_PROPERTY), myKey, new String("password").toCharArray(), certChain);
		
		keyManagerFactory.init(keyStore, keyStorePassword);

		m_sslContext.init(keyManagerFactory.getKeyManagers(), new TrustManager[] { new TrustEveryone() }, null);

		m_clientSocketFactory = m_sslContext.getSocketFactory();
		m_serverSocketFactory = m_sslContext.getServerSocketFactory(); 
	}

	public final ServerSocket createServerSocket(String localHost,
			int localPort,
			int timeout)
					throws IOException
	{
		final SSLServerSocket socket = (SSLServerSocket)m_serverSocketFactory.createServerSocket(localPort, 50, InetAddress.getByName(localHost));

		socket.setSoTimeout(timeout);

		socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

		return socket;
	}

	public final Socket createClientSocket(String remoteHost, int remotePort)
			throws IOException
	{
		final SSLSocket socket = (SSLSocket)m_clientSocketFactory.createSocket(remoteHost, remotePort);

		socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

		socket.startHandshake();

		return socket;
	}

	/**
	 * We're carrying out a MITM attack, we don't care whether the cert
	 * chains are trusted or not ;-)
	 *
	 */
	private static class TrustEveryone implements X509TrustManager
	{
		public void checkClientTrusted(X509Certificate[] chain, String authenticationType) {
		}

		public void checkServerTrusted(X509Certificate[] chain, String authenticationType) {
		}

		
		public java.security.cert.X509Certificate[] getAcceptedIssuers() {
			return null;
		}

		//@Override
		public void checkClientTrusted(
				java.security.cert.X509Certificate[] arg0, String arg1)
				throws CertificateException {
			
		}

		//@Override
		public void checkServerTrusted(
				java.security.cert.X509Certificate[] arg0, String arg1)
				throws CertificateException {
			
		}
	}
}

