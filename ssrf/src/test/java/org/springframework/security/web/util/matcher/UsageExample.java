package org.springframework.security.web.util.matcher;


import java.util.List;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.eclipse.jetty.client.HttpClient;

import org.springframework.boot.http.client.HttpComponentsFilteringDnsResolver;
import org.springframework.boot.http.client.JettyHttpClientFilteringDnsResolver;
import org.springframework.boot.http.client.NettyHttpClientFilteringAddressSelector;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;


public class UsageExample {

	public static void exampleApache() {
		System.out.println("Example Apache - Apache HttpClient with HttpComponentsDnsResolver");

		InetAddressFilter filter = InetAddressFilter.builder().blockExternal().build();
		HttpComponentsFilteringDnsResolver dnsResolver = new HttpComponentsFilteringDnsResolver(filter);

		Registry<ConnectionSocketFactory> factoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
				.register("http", PlainConnectionSocketFactory.getSocketFactory())
				.register("https", SSLConnectionSocketFactory.getSocketFactory())
				.build();

		CloseableHttpClient httpClient = HttpClientBuilder.create()
				.setConnectionManager(new BasicHttpClientConnectionManager(factoryRegistry, null, null, dnsResolver))
				.build();

		RestTemplate restTemplate = new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient));

		// 4. Use the RestTemplate to make a request
		System.out.println("Attempting to access http://google.com\n");

		try {
			ResponseEntity<String> response = restTemplate.getForEntity("https://google.com", String.class);
			System.out.println("FAILURE - Response: " + response.getBody());
		} catch (Exception e) {
			System.err.println("SUCCESS - Access blocked: " + e.getMessage());
		}
	}


	static void main(String[] args) {
		exampleApache();
		exampleNetty();
		exampleJetty();
	}

	public static void exampleJetty() {
		System.out.println("\nExample Jetty - Jetty HttpClient with JettyHttpClientDnsResolver");

		InetAddressFilter filter = InetAddressFilter.builder()
				.denyList(List.of("192.168.1.100")) // Example: deny a specific private IP
				.blockInternal()    // Example: block all internal IPs (like 127.0.0.1)
				.build();

		JettyHttpClientFilteringDnsResolver dnsResolver = new JettyHttpClientFilteringDnsResolver(filter);

		// 3. Create and configure Jetty's HttpClient
		HttpClient client = new HttpClient();
		client.setSocketAddressResolver(dnsResolver);

		try {
			client.start(); // Jetty HttpClient must be started

			// 4. Use the HttpClient to make a request
			// Example: trying to access a blocked internal address
			System.out.println("\nAttempting to access http://localhost (should be blocked by blockAllInternal=true)\n");
			try {
				org.eclipse.jetty.client.api.ContentResponse response = client.newRequest("http://localhost:8080").send(); // Jetty 11.x API
				System.out.println("FAILURE: Response from http://localhost: " + response.getContentAsString());
			} catch (Exception e) {
				// We expect an exception here, often a form of ConnectTimeoutException or similar
				// because the resolution will yield no valid addresses if localhost is blocked.
				// Jetty's behavior on no resolvable address might vary (e.g. timeout or specific exception).
				System.err.println("SUCCESS: Access to http://localhost blocked or failed as expected: " + e.getClass().getName() + " - " + e.getMessage());
			}

			// Example: trying to access an external address (should be allowed if not in deny list and DNS resolves)
			System.out.println("\nAttempting to access http://example.com (should be allowed)\n");
			try {
				org.eclipse.jetty.client.api.ContentResponse response = client.newRequest("http://example.com").send(); // Jetty 11.x API
				System.out.println("SUCCESS: Response from http://example.com: " + response.getContentAsString().substring(0, Math.min(response.getContentAsString().length(), 100)) + "...");
			} catch (Exception e) {
				System.err.println("FAILURE: Access to http://example.com failed: " + e.getMessage());
			}

			client.stop(); // Stop the client

		} catch (Exception e) {
			System.err.println("Error setting up or using Jetty HttpClient: " + e.getMessage());
			e.printStackTrace();
		}
	}

	public static void exampleNetty() {
		System.out.println("\nExample Netty - Reactor Netty HttpClient with NettyHttpClientAddressSelector\n");

		// 1. Create SecurityDnsHandler with custom logic
		InetAddressFilter filter = InetAddressFilter.builder()
		.blockExternal()
		.allowList(List.of("1.1.1.1", "8.8.4.4","google.com")) // Example: only allow specific public IPs
		.build();

		// 2. Create NettyHttpClientAddressSelector with the custom SecurityDnsHandler
		NettyHttpClientFilteringAddressSelector selector = new NettyHttpClientFilteringAddressSelector(filter);

		// 3. Create a Reactor Netty HttpClient with the custom addressSelector
		reactor.netty.http.client.HttpClient nettyHttpClient = reactor.netty.http.client.HttpClient.create()
				.resolvedAddressesSelector(selector);

		// 4. Use the WebClient with the configured HttpClient to make a request
		// The following WebClient setup requires spring-webflux dependency.
		// Commenting out to allow compilation without it, to focus on the selector's role.
		WebClient webClient = WebClient.builder()
				.clientConnector(new ReactorClientHttpConnector(nettyHttpClient))
				.build();

		System.out.println("Attempting to access http://example.com (should be blocked as not in allowList)\n");
		try {
			String response = webClient.get()
					.uri("http://example.com") // example.com IP is likely not 1.1.1.1 or 8.8.8.8
					.retrieve()
					.bodyToMono(String.class)
					.block();
			System.out.println("FAILURE: Response from http://example.com: " + response.substring(0, Math.min(response.length(), 100)) + "...");
		} catch (Exception e) {
			System.err.println("SUCCESS: Access to http://example.com blocked or failed as expected: " + e.getMessage());
		}

		System.out.println("\nAttempting to access http://1.1.1.1 (should be allowed if 1.1.1.1 is reachable)\n");
		try {
			// Note: 1.1.1.1 might not be serving HTTP or could be firewalled.
			// This is to demonstrate the selector allowing the attempt.
			String response = webClient.get()
					.uri("http://1.1.1.1")
					.retrieve()
					.bodyToMono(String.class)
					.block(java.time.Duration.ofSeconds(5)); // Timeout for potentially unresponsive IP
			System.out.println("SUCCESS: Response from http://1.1.1.1: " + response.substring(0, Math.min(response.length(), 100)) + "...");
		} catch (Exception e) {
			System.err.println("FAILURE: Access to http://1.1.1.1 blocked or failed as expected: " + e.getMessage());
		}
	}
}
