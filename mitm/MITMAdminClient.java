/**
 * CS255 project 2
 */
package mitm;

import java.io.*;
import java.net.*;
import java.security.SecureRandom;

public class MITMAdminClient
{
	private Socket m_remoteSocket;
	private String username;
	private String password;
	private String command;
	private String commonName = "";
	private String mode = "0";

	public static void main( String [] args ) {
		MITMAdminClient admin = new MITMAdminClient( args );
		
		admin.run();
	}

	private Error printUsage() {
		System.err.println(
				"\n" +
						"Usage: " +
						"\n java " + MITMAdminClient.class + " <options>" +
						"\n" +
						"\n Where options can include:" +
						"\n" +
						"\n   <-userName <type> >       " +
						"\n   <-userPassword <pass> >   " +
						"\n   <-cmd <shudown|stats>" +
						"\n   [-remoteHost <host name/ip>]  Default is localhost" +
						"\n   [-remotePort <port>]          Default is 8002" +
						"\n   [-mode <mode>]          		0 is normal, 1 is Challenger/Response, default is 0" +
						"\n"
				);

		System.exit(1);
		return null;
	}

	private MITMAdminClient( String [] args ) {
		int remotePort = 8002;
		String remoteHost = "localhost";

		if( args.length < 3 )
			throw printUsage();

		try {
			for (int i=0; i<args.length; i++)
			{
				if (args[i].equals("-remoteHost")) {
					remoteHost = args[++i];
				} else if (args[i].equals("-remotePort")) {
					remotePort = Integer.parseInt(args[++i]);
				} else if (args[i].equals("-userName")) {
					username = args[++i];
				} else if (args[i].equals("-userPassword")) {
					password = args[++i];
				} else if (args[i].equals("-cmd")) {
					command = args[++i];
					if( command.equals("enable") || command.equals("disable") ) {
						commonName = args[++i];
					}
				} else if (args[i].equals("-mode")) {
					mode = args[++i];
					if(!mode.equals("0") && !mode.equals("1")) {
						throw printUsage();
					}
				} else {
					throw printUsage();
				}
			}

			// DONETODO upgrade this to an SSL connection
//			m_remoteSocket = new Socket( remoteHost, remotePort);
			
			MITMSSLSocketFactory sslSocketFactory = new MITMSSLSocketFactory();
			m_remoteSocket = sslSocketFactory.createClientSocket(remoteHost, remotePort);

		}
		catch (Exception e) {
			throw printUsage();
		}

	}

	public void run() 
	{
		if(mode.equals("0")) {
			this.runNormal();
		} else if(mode.equals("1")) {
			this.runChallengeResponse();
		}
	}
	
	/**
	 * runs the normal authentication mode where the password is sent
	 */
	public void runNormal() {
		try {
			if( m_remoteSocket != null ) {
				PrintWriter writer = new PrintWriter( m_remoteSocket.getOutputStream() );
				writer.println("username:"+username);
				writer.println("password:"+password);
				writer.println("command:"+command);
				writer.println("mode:"+mode);
				writer.println("CN:"+commonName);
				writer.flush();
			}

			// now read back any response

			System.out.println("");
			System.out.println("Receiving input from MITM proxy:");
			System.out.println("");
			BufferedReader r = new BufferedReader(new InputStreamReader(m_remoteSocket.getInputStream()));
			String line = null;
			while ((line = r.readLine()) != null) {
				System.out.println(line);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.err.println("Admin Client exited");
		System.exit(0);
	}
	
	
	/**
	 * runs the challenge/response mode of authentication where the password is not sent
	 */
	public void runChallengeResponse() {
		try {
			PrintWriter writer = null;
			if( m_remoteSocket != null ) {
				writer = new PrintWriter( m_remoteSocket.getOutputStream() );
				writer.println("username:"+username);
				writer.println("password:"+password);
				writer.println("command:"+command);
				writer.println("mode:"+mode);
				writer.println("CN:"+commonName);
				writer.flush();
			}

			// now read back any response

			System.out.println("");
			System.out.println("Starting Challenge Response:");
			System.out.println("");
			BufferedReader r = new BufferedReader(new InputStreamReader(m_remoteSocket.getInputStream()));
			SecureRandom secureRandom = new SecureRandom();
			
			String saltString = r.readLine();
			byte[] salt = PasswordUtil.stringToBytes(saltString, ",");
//			System.out.println(new String(salt));
			
			// compute the secret
			byte[] secret = PasswordUtil.SHAsum(PasswordUtil.concatBytes(salt, password.getBytes()));
			
			// generate client challenge value
			byte[] cc = new byte[20];
			secureRandom.nextBytes(cc);
			
			// get sc
			String scString = r.readLine();
			byte[] sc = PasswordUtil.stringToBytes(scString, ",");
			
			// cr = hash(cc + sc + secret)
			byte[] cr = PasswordUtil.SHAsum(PasswordUtil.concatBytes(PasswordUtil.concatBytes(cc, sc), secret));
			
			// send cr and cc
			writer.println(PasswordUtil.bytesToString(cr, ","));
			writer.println(PasswordUtil.bytesToString(cc, ","));
			writer.flush();
			
			// see what the server says
			String line = null;
			while ((line = r.readLine()) != null) {
				System.out.println(line);
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.err.println("Admin Client exited");
		System.exit(0);
	}
	
	
	
	
	
	
	
	
	
}