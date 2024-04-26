///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3
//DEPS info.picocli:picocli-codegen:4.6.3

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.Charset;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

@Command(name = "XdgSaml", mixinStandardHelpOptions = true, version = "0.1", description = "retrieve saml token with xdg open")
class XdgOpenSaml implements Callable<Integer> {


	@Parameters(index = "0", description = "The server to call")
	private String server;
	
	@Option(names = { "--port", "-p" }, description = "port to listen for redirect", defaultValue = "8020")
	int port;

	@Option(names = { "--realm", "-r" }, description = "The authentication realm.", required = false)
	private Optional<String> realm;
	
	@Option(names = { "--trust-all", "-t" }, description = "ignore  ssl certificate validation", defaultValue = "false")
	private boolean trustAllCertificate;

	
	private final static String idName = "id";
	private final static String regex = "^[A-Z]*\\s+" // verb
			+ "[^\\s?]" // base url
			+ "+\\?" // ?
			+ "(?:[^\\s&?]+&)*" // other parameters
			+ idName + "=([^\\s&?=]+)" // token parameter
			+ "(?:&[^\\s&?]+)*" // other parameters
			+ "\\s+HTTP/[\\d]+(?:[\\.][\\d]+)$" // http version
	;
	private final static Pattern pattern = Pattern.compile(regex);

	private static final String SVPNCOOKIE = "SVPNCOOKIE";

	private static final Charset CHARSET = Charset.forName("UTF-8");
	private final static X509ExtendedTrustManager noTrustManager = createNoTrustManager();

	public static void main(String... args) {
		System.exit(new CommandLine(new XdgOpenSaml()).execute(args));
	}

	@Override
	public Integer call() throws Exception { // your business logic goes here...
		String serverUrl = "https://" + server;
		String id = retrieveId(serverUrl + "/remote/saml/start?redirect=1" + realm.map(r->"&realm="+r).orElse(""));
		String cookie = retrieveCookie(serverUrl + "/remote/saml/auth_id?id=" + id);
		
		System.out.println(cookie); 
		
		return 0;
	}
	
	
	
	private String retrieveId(String url) throws IOException, XdgOpenSaml.CannotRetrieveException {
		try (ServerSocket serverSocket = new ServerSocket(port)) {

			Runtime.getRuntime()
					.exec(new String[] { "xdg-open", url });

			Socket clientSocket = serverSocket.accept();
			BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true, CHARSET);

			String requestUrl = in.readLine();
			Matcher matcher = pattern.matcher(requestUrl);
			
			if (matcher.matches()) {
				writeResponse(out, "XdgOpenSaml ID Retrieved! Start retrieving cookie...");
				return matcher.group(1);
			} else {
				String message = "ERROR: Redirect does not contain \"" + idName + "\" parameter";
				writeResponse(out, message);
				throw new CannotRetrieveException(message);
			}


		}
	}

	private String retrieveCookie(String url) throws URISyntaxException, NoSuchAlgorithmException, KeyManagementException,
			IOException, InterruptedException, XdgOpenSaml.CannotRetrieveException {
		HttpRequest httpRequest = HttpRequest.newBuilder()
				.uri(new URI(url)).GET().build();

		SSLContext sslContext;
		if (trustAllCertificate) {
			sslContext = SSLContext.getInstance("TLS");
			sslContext.init(null, new TrustManager[] { noTrustManager }, new SecureRandom());
		} else {
			sslContext = SSLContext.getDefault();
		}

		HttpClient client = HttpClient.newBuilder().sslContext(sslContext).build();

		HttpResponse<Stream<String>> response = client.send(httpRequest, BodyHandlers.ofLines());
		var code = response.statusCode();

		if (code < 400) {
			String svpnCoockie = response.headers().allValues("set-cookie").stream()
					.filter(s -> s.startsWith(SVPNCOOKIE)).findAny().map(s -> s.split(";")[0])
					.orElseThrow(()->new CannotRetrieveException("Missing "+SVPNCOOKIE+" in response"));
			return svpnCoockie;
		} else {
			throw new CannotRetrieveException("Error retrieving Cookie [" + code +"]\"" + response.body()  );
		}
	}

	private void writeResponse(PrintWriter out, String body) {

		out.println("HTTP/3 200");
		out.println("Server 0");
		out.println("content-type: text/html; charset=" + CHARSET.name());
		out.println("content-length: " + body.getBytes(CHARSET).length);
		out.println("");
		out.println(body);
		out.println("");
	}
	
	private final static class CannotRetrieveException extends Exception{
		public CannotRetrieveException(String message) {
			super(message);
		}
	}
	
	private static X509ExtendedTrustManager createNoTrustManager() {
		return new X509ExtendedTrustManager() {
			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return new X509Certificate[] {};
			}

			@Override
			public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
			}

			
			@Override
			public void checkClientTrusted(final X509Certificate[] chain, final String authType, final Socket socket) {
			}

			@Override
			public void checkServerTrusted(final X509Certificate[] chain, final String authType, final Socket socket) {
			}

			@Override
			public void checkClientTrusted(final X509Certificate[] chain, final String authType,
					final SSLEngine engine) {
			}

			@Override
			public void checkServerTrusted(final X509Certificate[] chain, final String authType,
					final SSLEngine engine) {
			}

			@Override
			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			}
		};
	}
}
