package com.huateng.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


class SSLClient {

	private SSLSocket socket = null;
	
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
	 * 创建SSLSocket 不验证服务器证书
	 * @throws Exception
	 */
	public void createNotVerifySSLSocket() throws Exception {
		 // key store相关信息  
	    String keyName = "sslclientkeys";  
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
	    SSLSocketFactory factory = context.getSocketFactory();
		
		// 通过套接字工厂，获取一个客户端套接字
//		SSLSocketFactory socketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		socket = (SSLSocket) factory.createSocket("localhost", 7070);
	}
	
	/**
	 * 创建SSLSocket 不验证服务器证书
	 * @throws Exception
	 */
	public void createVerifySSLSocket() throws Exception {
		String host = "localhost";
        int port = 7070;
        String keyf = "sslclientkeys";
        String trustf = "sslclienttrust";
        String pass = "123456";
        
        SSLContext ctx = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
        KeyStore ks = KeyStore.getInstance("JKS");
        KeyStore tks = KeyStore.getInstance("JKS");
        
        InputStream keyfin = SSLServer.class.getClassLoader().getResourceAsStream(keyf);
        InputStream trustfin = SSLServer.class.getClassLoader().getResourceAsStream(trustf);
        ks.load(keyfin, pass.toCharArray());
        tks.load(trustfin, pass.toCharArray());
        kmf.init(ks, pass.toCharArray());
        tmf.init(tks);
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        SSLSocketFactory ssf = ctx.getSocketFactory();
        
        socket = (SSLSocket) ssf.createSocket(host, port);
	}

	public SSLClient() throws Exception {
		createVerifySSLSocket();
	}

	public void connect() {
		try {
			// 获取客户端套接字输出流
			PrintWriter output = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
			// 将用户名和密码通过输出流发送到服务器端
			String userName = "principal";
			output.println(userName);
			String password = "credential";
			output.println(password);
			output.flush();

			// 获取客户端套接字输入流
			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			// 从输入流中读取服务器端传送的数据内容，并打印出来
			String response = input.readLine();
			response += "\n " + input.readLine();
			System.out.println(response);

			// 关闭流资源和套接字资源
			output.close();
			input.close();
			socket.close();
		} catch (IOException ioException) {
			ioException.printStackTrace();
		} finally {
			System.exit(0);
		}
	}

	public static void main(String args[]) throws Exception {
		new SSLClient().connect();
	}
}
