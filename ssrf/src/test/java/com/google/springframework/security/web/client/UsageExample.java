package com.google.springframework.security.web.client;

import static com.google.springframework.security.web.client.NetworkMode.BLOCK_EXTERNAL;
import static com.google.springframework.security.web.client.NetworkMode.BLOCK_INTERNAL;
import static org.springframework.http.MediaType.TEXT_HTML;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.util.Timeout;
import org.eclipse.jetty.client.HttpClient;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.JettyClientHttpRequestFactory;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;


public class UsageExample {

	public static void example8() {
		System.out.println("Example 8 (WebClient - Netty - should be blocked)");

		// 2. Create a Reactor Netty HttpClient (default settings are fine for this example)
		reactor.netty.http.client.HttpClient nettyClient = reactor.netty.http.client.HttpClient.create();

		// 3. Create the SecureRestTemplate.Builder and configure it for Netty
		SecureRestTemplate.Builder builder = new SecureRestTemplate.Builder()
				.fromNettyClient(nettyClient)  // Use the Netty client
				.reportOnly(false) // 'false' to block, 'true' to report only
				.withCustomFilter(new BasicSsrfProtectionFilter(BLOCK_EXTERNAL));

		// 4. Get the ClientHttpConnector (this integrates the SSRF protection)
		ClientHttpConnector connector = builder.buildToClientHttpConnector();

		// 5. Create a WebClient using the connector
		WebClient webClient = WebClient.builder()
				.clientConnector(connector)
				.build();

		// 6. Make a request to a BLOCKED URL (e.g., google.com)
		Mono<String> blockedResponseMono = webClient.get()
				.uri("https://www.google.com") // This *should* be blocked
				.retrieve()
				.bodyToMono(String.class);

		blockedResponseMono.subscribe(
				response -> {
					// Should NOT be reached if blocking is enabled
					System.out.println("BLOCKED Request - Unexpected Success: " + response);
				},
				error -> {
					// *Should* be reached if blocking is enabled
					System.err.println("BLOCKED Request - Expected Failure: " + error.getMessage());
				}
		);

		// Keep the application running (for demonstration purposes only)
		try {
			Thread.sleep(5000); // Wait for the asynchronous request to complete
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	public static void example7() {
		System.out.println("Example 7");
		RestClient exampleClient = RestClient.create(new SecureRestTemplate.Builder().
				networkMode(BLOCK_EXTERNAL).build());

		try {
			exampleClient.get()
					.uri("https://google.com")
					.accept(TEXT_HTML)
					.retrieve()
					.body(String.class);
		} catch (Exception e) {
			System.err.println("Access blocked: " + e.getMessage());
		}
	}

	public static void example6() {
		System.out.println("Example 6");

		ClientHttpRequestFactory clientHttpRequestFactory = new SecureRestTemplate.Builder()
				.reportOnly(true) // Log warning about blocking, but don't block
				.networkMode(BLOCK_EXTERNAL)
				.withCustomFilter(
						addresses -> Arrays.stream(addresses).filter(a -> !a.isMCNodeLocal())
								.toArray(InetAddress[]::new)).withBlocklist("evil.com", "6.6.6.9/16", "123.123.123.123")
				.buildToHttpRequestFactory();

		if (clientHttpRequestFactory instanceof HttpComponentsClientHttpRequestFactory) {
			HttpComponentsClientHttpRequestFactory factory = (HttpComponentsClientHttpRequestFactory) clientHttpRequestFactory;
			factory.setConnectTimeout(1000);
		}

		// a secure RestTemplate can be still built
		RestTemplate secureRestTemplate = new RestTemplate(clientHttpRequestFactory);

		try {
			ResponseEntity<String> result = secureRestTemplate.getForEntity("https://google.com", String.class);
			System.out.println(result);
		} catch (Exception e) {
			// This should not run
			System.err.println("Access blocked: " + e.getMessage());
		}
	}

	public static void example5() {
		System.out.println("Example 5");

		// For SSRF prevention the "magic is built into the DNS resolver"
		DnsResolver dnsResolver = new SecureRestTemplate.Builder()
				.reportOnly(true) // Log warning about blocking, but don't block
				.networkMode(BLOCK_EXTERNAL)
				.withCustomFilter(
						addresses -> Arrays.stream(addresses).filter(a -> !a.isMCNodeLocal())
								.toArray(InetAddress[]::new)).withBlocklist("evil.com", "6.6.6.9/16", "123.123.123.123")
				.buildToHttpClientDnsResolver();

		// When a very custom client is needed
		Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
				.register("http", PlainConnectionSocketFactory.getSocketFactory())
				.register("https", SSLConnectionSocketFactory.getSocketFactory()).build();

		BasicHttpClientConnectionManager connManager = new BasicHttpClientConnectionManager(registry, null,
				null,
				dnsResolver);

		// with custom timeout
		connManager.setConnectionConfig(ConnectionConfig.custom().setConnectTimeout(Timeout.ofMinutes(2)).build());
		// with custom TLS config
		connManager.setTlsConfig(TlsConfig.custom().setSupportedCipherSuites("TLSv1-3").build());

		CloseableHttpClient httpClient = HttpClientBuilder.create().setConnectionManager(connManager).build();

		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(
				httpClient);

		// a secure RestTemplate can be still built
		RestTemplate secureRestTemplate = new RestTemplate(requestFactory);

		try {
			ResponseEntity<String> result = secureRestTemplate.getForEntity("https://google.com", String.class);
			System.out.println(result);
		} catch (Exception e) {
			// This should not run
			System.err.println("Access blocked: " + e.getMessage());
		}
	}

	/**
	 * Showcasing the configuration to be used for a Jetty HttpClient based RestTemplate
	 */
	@Configuration
	public static class ExampleConfig4 {

		@Bean
		HttpClient jettyClient() {
			return new HttpClient();
		}

		@Bean
		JettyClientHttpRequestFactory jettyClientHttpRequestFactory(HttpClient jettyClient) {
			// This bean manages the lifecycle of (starts/stops) the HttpClient
			return new JettyClientHttpRequestFactory(jettyClient);
		}

		@Bean("secureRestTemplate")
		RestTemplate secureRestTemplate(HttpClient jettyClient) {
			return new SecureRestTemplate.Builder()
					.fromJettyClient(jettyClient)
					.reportOnly(true) // Log warning about blocking, but don't block
					.networkMode(BLOCK_EXTERNAL)
					.withCustomFilter(addresses -> Arrays.stream(addresses).filter(a -> !a.isMCNodeLocal())
							.toArray(InetAddress[]::new)).withBlocklist("evil.com", "6.6.6.9/16", "123.123.123.123")
					.build();
		}
	}

	@Component
	public static class Example4App {

		@Autowired
		RestTemplate secureRestTemplate;

		public void run() {

			try {
				ResponseEntity<String> result = secureRestTemplate.getForEntity("https://google.com", String.class);
				System.out.println(result);
			} catch (Exception e) {
				// This should not run
				System.err.println("Access blocked: " + e.getMessage());
			}

		}
	}

	public static void example4() {
		System.out.println("Example 4");
		// Barebone spring application to demonstrate Jetty client usage above
		AnnotationConfigApplicationContext ctx = new AnnotationConfigApplicationContext();
		ctx.register(ExampleConfig4.class);
		ctx.register(Example4App.class);
		ctx.refresh();
		ctx.start();

		Example4App app = ctx.getBean(Example4App.class);
		app.run();

		ctx.close();
	}


	public static void example3() {
		System.out.println("Example 3");
		RestTemplate exampleTemplate = new SecureRestTemplate.Builder()
				.reportOnly(true) // Log warning about blocking, but don't block
				.networkMode(BLOCK_EXTERNAL)
				.withCustomFilter(
						addresses -> Arrays.stream(addresses).filter(a -> !a.isMCNodeLocal())
								.toArray(InetAddress[]::new)).withBlocklist("evil.com", "6.6.6.9/16", "123.123.123.123")
				.build();

		try {
			ResponseEntity<String> result = exampleTemplate.getForEntity("https://google.com", String.class);
			System.out.println(result);
		} catch (Exception e) {
			// This should not run
			System.err.println("Access blocked: " + e.getMessage());
		}
	}


	public static void example2() {
		System.out.println("Example 2");
		RestTemplate exampleTemplate = new SecureRestTemplate.Builder().
				networkMode(BLOCK_EXTERNAL)
				.build();

		try {
			exampleTemplate.getForEntity("https://google.com", String.class);
		} catch (Exception e) {
			System.err.println("Access blocked: " + e.getMessage());
		}

		// This should print:
		// Access blocked: I/O error on GET request for "https://google.com": Access to google.com was blocked because it violates the SSRF protection config

	}

	public static void example1() {
		System.out.println("Example 1");
		// run with `-Dssrf.protection.mode=deny_list -Dssrf.protection.iplist=127.0.0.1,192.168.0.0/16`
		// if the properties are not set accordingly it will fail with IllegalStateException

		// for this example:
		System.setProperty("ssrf.protection.mode", "deny_list");
		System.setProperty("ssrf.protection.iplist", "127.0.0.1,192.168.0.0/16");

		RestTemplate exampleTemplate = SecureRestTemplate.buildDefault();
		exampleTemplate.getForEntity("https://google.com", String.class);
	}

	public static void main(String[] args) {
		// example1();
		// example2();
		// example3();
		// example4();
		// example5();
		// example6();
		// example7();
		example8();
	}


}

