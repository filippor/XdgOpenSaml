///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3
//DEPS info.picocli:picocli-codegen:4.6.3

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

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

	private final static String ID_PARAMETER_NAME = "id";

	private static final String COOKIE_NAME = "SVPNCOOKIE";

	private final static X509ExtendedTrustManager noTrustManager = createNoTrustManager();

	public static void main(String... args) {
		System.exit(new CommandLine(new XdgOpenSaml()).execute(args));
	}

	@Override
	public Integer call() throws Exception { // your business logic goes here...
		String serverUrl = "https://" + server;

		String id = retrieveId(serverUrl + "/remote/saml/start?redirect=1" + realm.map(r -> "&realm=" + r).orElse(""));
		String cookie = retrieveCookie(serverUrl + "/remote/saml/auth_id?id=" + id);

		System.out.println(cookie);

		return 0;
	}

	private String retrieveId(String url) throws XdgOpenSaml.CannotRetrieveException, InterruptedException, IOException,
			ExecutionException, TimeoutException {
		InetAddress localAddress = InetAddress.getByName("127.0.0.1");
		HttpServer server = HttpServer.create(new InetSocketAddress(localAddress, port), 0);
		CompletableFuture<Optional<String>> idResult = new CompletableFuture<>();
		String errorMessage = "ERROR: Redirect does not contain \"" + ID_PARAMETER_NAME + "\" parameter";
		try {
			server.createContext("/", exchange -> {
				String requestQuery = exchange.getRequestURI().getQuery();
				Optional<String> id = Arrays.stream(requestQuery.split("&")).filter(s -> s.startsWith(ID_PARAMETER_NAME)).findAny()
						.map(s -> s.substring(s.indexOf('=')));
				if (id.isPresent()) {
					sendResponse(exchange, 200, XdgOpenSaml.class.getSimpleName() + " Retrieved Id! Start retrieving token ...");
				}else {
					sendResponse(exchange, 500, errorMessage);
				}
				idResult.complete(id);
			});
			server.start();
			Runtime.getRuntime().exec(new String[] { "xdg-open", url });
			return idResult.get(5, TimeUnit.MINUTES).orElseThrow(() -> new CannotRetrieveException(errorMessage));
		} finally {
			server.stop(0);
		}

	}

	private void sendResponse(HttpExchange exchange, int code, String message) throws IOException {
		exchange.sendResponseHeaders(code, message.length());
		try (OutputStream stream = exchange.getResponseBody()) {
			stream.write(message.getBytes());
		}
	}

	private String retrieveCookie(String url) throws URISyntaxException, NoSuchAlgorithmException,
			KeyManagementException, IOException, InterruptedException, XdgOpenSaml.CannotRetrieveException {
		HttpRequest httpRequest = HttpRequest.newBuilder().uri(new URI(url)).GET().build();

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
					.filter(s -> s.startsWith(COOKIE_NAME)).findAny().map(s -> s.split(";")[0])
					.orElseThrow(() -> new CannotRetrieveException("Missing " + COOKIE_NAME + " in response"));
			return svpnCoockie;
		} else {
			throw new CannotRetrieveException("Error retrieving Cookie [" + code + "]\"\n" + response.body().collect(Collectors.joining("\n")));
		}
	}

	private final static class CannotRetrieveException extends Exception {
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
