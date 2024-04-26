///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3
//DEPS info.picocli:picocli-codegen:4.6.3

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
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
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * @author filippor(filippo.rossoni@gmail.com)
 */
@Command(name = "XdgOpenSaml", mixinStandardHelpOptions = true, version = "0.2", description = "retrieve saml token with xdg open")
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

		String cookie = retrieveCookie(serverUrl);

		System.out.println(cookie);

		return 0;
	}

	private String retrieveCookie(String url) throws XdgOpenSaml.CannotRetrieveException, InterruptedException,
			IOException, ExecutionException, TimeoutException {
		InetAddress localAddress = InetAddress.getByName("127.0.0.1");
		HttpServer server = HttpServer.create(new InetSocketAddress(localAddress, port), 0);

		CompletableFuture<String> cookieResult = new CompletableFuture<>();
		try {
			server.createContext("/", new CookieRetrieverHttpHandler(cookieResult, url));
			server.start();

			Runtime.getRuntime().exec(new String[] { "xdg-open",
					url + "/remote/saml/start?redirect=1" + realm.map(r -> "&realm=" + r).orElse("") });

			return cookieResult.get(5, TimeUnit.MINUTES);
		} finally {
			server.stop(1);
		}

	}

	private final class CookieRetrieverHttpHandler implements HttpHandler {
		private final CompletableFuture<String> cookieResult;
		private final String url;

		private CookieRetrieverHttpHandler(CompletableFuture<String> cookieResult, String url) {
			this.cookieResult = cookieResult;
			this.url = url;
		}

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			try {
				extractId(exchange.getRequestURI().getQuery()).ifPresentOrElse(id -> {
					String cookie = retrieveCookieFromId(id);
					sendResponse(exchange, 200,
							XdgOpenSaml.class.getSimpleName() + " Retrieved Cookie! Connecting ...");
					cookieResult.complete(cookie);
				}, () -> {
					String errorMessage = "ERROR: Redirect does not contain \"" + ID_PARAMETER_NAME + "\" parameter "
							+ exchange.getRequestURI();
					sendResponse(exchange, 500, errorMessage);
					cookieResult.completeExceptionally(new CannotRetrieveException(errorMessage));
				});
			} catch (Exception e) {
				sendResponse(exchange, 500, e.getMessage());
				cookieResult.completeExceptionally(e);
			}
		}

		private Optional<String> extractId(String requestQuery) {
			return Arrays.stream(requestQuery.split("&")).filter(s -> s.startsWith(ID_PARAMETER_NAME)).findAny()
					.map(s -> s.substring(s.indexOf('=')));
		}

		private void sendResponse(HttpExchange exchange, int code, String message) {
			try {
				exchange.sendResponseHeaders(code, message.length());
				try (OutputStream stream = exchange.getResponseBody()) {
					stream.write(message.getBytes());
				}
			} catch (IOException e) {
				// error in sending response to browser try to not fail token retrieve
				e.printStackTrace();
			}

		}

		private String retrieveCookieFromId(String id) {
			try {
				HttpRequest httpRequest = HttpRequest.newBuilder().uri(new URI(url + "/remote/saml/auth_id?id=" + id))
						.GET().build();
				SSLContext sslContext = SSLContext.getDefault();

				if (trustAllCertificate) {
					sslContext = SSLContext.getInstance("TLS");
					sslContext.init(null, new TrustManager[] { noTrustManager }, new SecureRandom());
				}

				HttpClient client = HttpClient.newBuilder().sslContext(sslContext).build();

				HttpResponse<Stream<String>> response = client.send(httpRequest, BodyHandlers.ofLines());
				if (response.statusCode() < 400) {
					return extractCookie(response);
				} else {
					throw new CannotRetrieveException("Error retrieving Cookie [" + response.statusCode() + "]\"\n"
							+ response.body().collect(Collectors.joining("\n")));
				}
			} catch (Exception e) {
				throw sneakyThrow(e);
			}
		}

		private String extractCookie(HttpResponse<Stream<String>> response) throws XdgOpenSaml.CannotRetrieveException {
			return response.headers().allValues("set-cookie").stream().filter(s -> s.startsWith(COOKIE_NAME)).findAny()
					.map(s -> s.split(";")[0])
					.orElseThrow(() -> new CannotRetrieveException("Missing " + COOKIE_NAME + " in response"));
		}

	}

	private final static class CannotRetrieveException extends Exception {
		public CannotRetrieveException(String message) {
			super(message);
		}
	}

	@SuppressWarnings("unchecked")
	public static <E extends Throwable> E sneakyThrow(Throwable e) throws E {
		throw (E) e;
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
