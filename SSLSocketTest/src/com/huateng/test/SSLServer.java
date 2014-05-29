package com.huateng.test;

import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

class SSLServer {

	// 服务器端授权的用户名和密码
	private static final String USER_NAME = "principal";
	private static final String PASSWORD = "credential";
	// 服务器端保密内容
	private static final String SECRET_CONTENT = "中国好 This is confidential content from server X, for your eye!";

	private SSLServerSocket serverSocket = null;
	
	class MyX509TrustManager implements X509TrustManager {

		@Override
		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			// TODO Auto-generated method stub
			
		}

		@Override
		public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			// TODO Auto-generated method stub
			
		}

		@Override
		public X509Certificate[] getAcceptedIssuers() {
			// TODO Auto-generated method stub
			return null;
		}
		
	}
	
	/**
	 * 创建SSLServerSocket 不验证客户端证书
	 * @throws Exception
	 */
	public void createNotVerifySSLServerSocket() throws Exception {
		// 通过套接字工厂，获取一个服务器端套接字
		 // key store相关信息  
	    String keyName = "sslserverkeys";  
	    char[] keyStorePwd = "123456".toCharArray();  
	    char[] keyPwd = "123456".toCharArray();  
	    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());  
	  
	    // 装载当前目录下的key store. 可用jdk中的keytool工具生成keystore  
	    InputStream in = null;
	    in = SSLServer.class.getClassLoader().getResourceAsStream(keyName);
	    keyStore.load(in, keyPwd);  
	    in.close();
	  
	    // 初始化key manager factory  
	    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory  
	            .getDefaultAlgorithm());  
	    kmf.init(keyStore, keyPwd);  
	  
	    // 初始化ssl context  
	    SSLContext context = SSLContext.getInstance("TLS");  
	    context.init(kmf.getKeyManagers(),  
	            new TrustManager[] { new MyX509TrustManager() },  
	            new SecureRandom());  
	  
	    // 监听和接收客户端连接  
	    SSLServerSocketFactory factory = context.getServerSocketFactory();
		
//		SSLServerSocketFactory socketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		serverSocket = (SSLServerSocket) factory.createServerSocket(7070);
	}
	
	/**
	 * 创建SSLServerSocket 验证客户端证书
	 * @throws Exception
	 */
	public void createVerifySSLServerSocket()  throws Exception {
		String type = "TLS";//类型
        String keyf = "sslserverkeys";//key文件路径
        String trustf = "sslservertrust";//信任证书库
        String pass = "123456";//密码
        int port = 7070;//端口
        //初始化上下文
        SSLContext ctx = SSLContext.getInstance(type);
        
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        
        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore tks = KeyStore.getInstance("JKS");
        
        //载入keystore
        InputStream keyfin = SSLServer.class.getClassLoader().getResourceAsStream(keyf);
        InputStream trustfin = SSLServer.class.getClassLoader().getResourceAsStream(trustf);
        ks.load(keyfin, pass.toCharArray());
        tks.load(trustfin, pass.toCharArray());
        
        kmf.init(ks, pass.toCharArray());
        tmf.init(tks);
        
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        
        serverSocket = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(port);
        serverSocket.setNeedClientAuth(true);//客户端认证
	}

	public SSLServer() throws Exception {
		createVerifySSLServerSocket();
	}

	private void runServer() { 
	 while (true) { 
		 try { 
			 System.out.println("Waiting for connection..."); 
			 // 服务器端套接字进入阻塞状态，等待来自客户端的连接请求
			 SSLSocket socket = (SSLSocket) serverSocket.accept(); 
			
			 // 获取服务器端套接字输入流
			 BufferedReader input = new BufferedReader( 
			        new InputStreamReader(socket.getInputStream())); 
		 // 从输入流中读取客户端用户名和密码
			 String userName = input.readLine(); 
			 String password = input.readLine(); 
			
			 // 获取服务器端套接字输出流
			 PrintWriter output = new PrintWriter( 
			        new OutputStreamWriter(socket.getOutputStream())); 

		 // 对请求进行认证，如果通过则将保密内容发送给客户端
			 if (userName.equals(USER_NAME) && password.equals(PASSWORD)) { 
				 output.println("Welcome, " + userName); 
				 output.println(SECRET_CONTENT); 
			 } else { 
				 output.println("Authentication failed, you have no access to server X..."); 
			 } 
		
		 // 关闭流资源和套接字资源
			 output.close(); 
			 input.close(); 
			 socket.close(); 

		 } catch (IOException ioException) { 
			 ioException.printStackTrace(); 
		 } 
	 } 
}	public static void main(String args[]) throws Exception {
		SSLServer server = new SSLServer();
		server.runServer();
	}
}
