///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.6.3
//DEPS info.picocli:picocli-codegen:4.6.3

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

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
class XdgOpenSamlId implements Callable<Integer> {

	@Parameters(index = "0", description = "The server to call")
	private String server;

	@Option(names = { "--port", "-p" }, description = "port to listen for redirect", defaultValue = "8020")
	int port;

	@Option(names = { "--realm", "-r" }, description = "The authentication realm.", required = false)
	private Optional<String> realm;

	private final static String ID_PARAMETER_NAME = "id";

	public static void main(String... args) {
		System.exit(new CommandLine(new XdgOpenSamlId()).execute(args));
	}

	@Override
	public Integer call() throws Exception { // your business logic goes here...
		String serverUrl = "https://" + server;

		String id = retrieveId(serverUrl);

		System.out.println("remote/saml/auth_id?id=%s".formatted(id));

		return 0;
	}

	private String retrieveId(String url)
			throws InterruptedException, IOException, ExecutionException, TimeoutException {
		InetAddress localAddress = InetAddress.getByName("127.0.0.1");
		HttpServer server = HttpServer.create(new InetSocketAddress(localAddress, port), 0);

		CompletableFuture<String> idResult = new CompletableFuture<>();
		try {
			server.createContext("/", new IdRetrieverHttpHandler(idResult));
			server.start();

			Runtime.getRuntime().exec(new String[] { "xdg-open",
					url + "/remote/saml/start?redirect=1" + realm.map(r -> "&realm=" + r).orElse("") });

			return idResult.get(5, TimeUnit.MINUTES);
		} finally {
			server.stop(1);
		}

	}

	private final class IdRetrieverHttpHandler implements HttpHandler {
		private final CompletableFuture<String> idResult;

		
		private IdRetrieverHttpHandler(CompletableFuture<String> idResult) {
			this.idResult = idResult;
		}

		@Override
		public void handle(HttpExchange exchange) throws IOException {
			try {
				extractId(exchange.getRequestURI().getQuery()).ifPresentOrElse(id -> {
					sendResponse(exchange, 200,
							XdgOpenSamlId.class.getSimpleName() + " Retrieved Id \"%s\" Connecting ...".formatted(id));
					idResult.complete(id);
				}, () -> {
					String errorMessage = "ERROR: Redirect does not contain \"" + ID_PARAMETER_NAME + "\" parameter "
							+ exchange.getRequestURI();
					sendResponse(exchange, 500, errorMessage);
					idResult.completeExceptionally(new CannotRetrieveException(errorMessage));
				});
			} catch (Exception e) {
				sendResponse(exchange, 500, e.getMessage());
				idResult.completeExceptionally(e);
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

		private final static class CannotRetrieveException extends Exception {
			public CannotRetrieveException(String message) {
				super(message);
			}
		}
	}
}

