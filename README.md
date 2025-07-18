# SSRF Protected `RestTemplate` Library

This library provides a framework for preventing Server-Side Request Forgery (SSRF) vulnerabilities in Java applications. It allows you to define and enforce rules for restricting which hosts, IP addresses and address ranges can be accessed by your application.

## Features

* **Flexible filtering:** Supports different filtering modes, including:
    * **Basic filtering:** Allow or block internal/external IP addresses.
    * **List-based filtering:** Allow or block specific IP addresses and ranges.
* **Customizable:** Easily integrate with your existing DNS resolution mechanism.
* **Extensible:**  Create your own custom filters to implement specific SSRF protection logic.

## Use Cases

### Mitigating SSRF in a Webhook Feature

**Scenario:** Imagine your application provides a webhook feature. Users can specify a URL, and your application's backend will send a POST request to that URL when a specific event occurs (e.g., a new order is placed).

**The Vulnerability:** A malicious user could configure the webhook URL to point to an internal service within your infrastructure that is not exposed to the public internet. For example:

*   `http://169.254.169.254/latest/meta-data/`: To access the EC2 instance metadata service in an AWS environment and potentially steal credentials.
*   `http://localhost:8080/admin/reset-database`: To access an internal administrative endpoint.
*   `http://internal-monitoring-service:9090/`: To scan for or interact with other internal services.

Without protection, your application's server would blindly make a request to these internal URLs, leading to a classic Server-Side Request Forgery (SSRF) vulnerability.

**The Solution:** By using this library, you can configure your HTTP client to prevent requests to internal or private IP addresses.

Here is how you would configure a `RestTemplate` with Apache's `HttpClient` to only allow requests to external, public IP addresses. This effectively blocks webhook calls to internal services:

```java
// 1. Create a SecurityDnsHandler to block requests to internal IP addresses.
SecurityDnsHandler securityDnsHandler = new SecurityDnsHandler.Builder()
    .blockAllInternal(true) // Block private, loopback, and site-local addresses.
    .build();

// 2. Create an HttpComponentsDnsResolver with the security handler.
HttpComponentsDnsResolver dnsResolver = new HttpComponentsDnsResolver(securityDnsHandler);

// 3. Configure a ConnectionManager with the custom DNS resolver.
// This ensures the resolver is used for both HTTP and HTTPS connections.
Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
    .register("http", PlainConnectionSocketFactory.getSocketFactory())
    .register("https", SSLConnectionSocketFactory.getSocketFactory())
    .build();
BasicHttpClientConnectionManager connectionManager = new BasicHttpClientConnectionManager(
    socketFactoryRegistry, null, null, dnsResolver);

// 4. Build an Apache HttpClient with the custom connection manager.
CloseableHttpClient httpClient = HttpClientBuilder.create()
    .setConnectionManager(connectionManager)
    .build();

// 5. Create a RestTemplate that uses the secure HttpClient.
RestTemplate webhookTemplate = new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient));

// Now, use this template to send webhooks safely.
// Object payload = ...;
// This call will succeed if api.customer.com resolves to a public IP.
webhookTemplate.postForEntity("https://api.customer.com/webhook", payload, String.class);

// This call will be blocked by the library and throw an exception.
webhookTemplate.postForEntity("http://169.254.169.254/latest/meta-data/", payload, String.class);
```

This configuration ensures that your webhook feature cannot be abused to attack your internal infrastructure.

### Securing Outgoing API Calls to Trusted Partners

**Scenario:** Your application integrates with a limited set of trusted, third-party APIs. For example, it might need to fetch data from a payment provider like Stripe and a CRM like Salesforce. For security and compliance reasons, you want to ensure your application server can *only* make outgoing requests to these specific services.

**The Vulnerability:** Without strict egress controls, an SSRF vulnerability in your application could be exploited by an attacker. The attacker could force your server to make requests to an external, malicious server that they control. This could be used to:

*   Exfiltrate sensitive data (e.g., environment variables, database secrets).
*   Use your server as a proxy to attack other systems.
*   Download and execute malware onto your server.

**The Solution:** You can use this library's allowlist feature to create a `RestTemplate` that is only capable of communicating with the domains of your trusted partners. All other outgoing requests will be blocked at the DNS resolution level.

```java
// 1. Create a SecurityDnsHandler that only allows requests to specific domains.
SecurityDnsHandler securityDnsHandler = new SecurityDnsHandler.Builder()
    .allowList("api.stripe.com", "my-company.my.salesforce.com")
    .build();

// 2. Create an HttpComponentsDnsResolver with the security handler.
HttpComponentsDnsResolver dnsResolver = new HttpComponentsDnsResolver(securityDnsHandler);

// 3. Configure and build an Apache HttpClient and RestTemplate as shown in the previous example.
// ... (full configuration omitted for brevity)
CloseableHttpClient httpClient = buildSecureHttpClient(dnsResolver);
RestTemplate trustedApiTemplate = new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient));

// This call will SUCCEED because api.stripe.com is in the allowlist.
trustedApiTemplate.getForEntity("https://api.stripe.com/v1/balance", String.class);

// This call will be BLOCKED and throw an exception because the domain is not in the allowlist.
trustedApiTemplate.getForEntity("https://api.malicious-attacker.com/exfiltrate", String.class);
```

This "zero trust" approach ensures that even if a vulnerability is found, the potential damage is limited because the application is prevented from communicating with unauthorized hosts.

## Limitations

This is the first iteration of the library. Currently the `RestTemplate` is backed by an Apache Commons 5 HttpClient.
Support for Jetty's `HttpClient` and Reactor Netty's `HttpClient` is also available.

## Usage

```java
RestTemplate exampleTemplate = new SecureRestTemplate.Builder()
    .reportOnly(true) // Log warning about blocking, but don't block
    .networkMode(BLOCK_EXTERNAL)
    .withCustomFilter(addresses ->
        Arrays.stream(addresses).filter(a -> !a.isMCNodeLocal()).toArray(InetAddress[]::new)
    )
    .withBlocklist("evil.com", "6.6.6.9/16", "123.123.123.123")
    .build();

try {
    ResponseEntity<String> result = exampleTemplate.getForEntity("https://google.com", String.class);
    System.out.println(result);
} catch (Exception e) {
    // This should not run
    System.err.println("Access blocked: " + e.getMessage());
}
```

### Using with Jetty's HttpClient

To use the SSRF protection with Jetty's `HttpClient`, you can configure it with `JettyHttpClientDnsResolver`:

```java
import org.eclipse.jetty.client.HttpClient;
import client.JettyHttpClientDnsResolver;
import client.dns.SecurityDnsHandler;

// ...

SecurityDnsHandler securityDnsHandler = SecurityDnsHandler.builder()
    .denyList("192.168.1.100") // Example: deny a specific IP
    .blockAllInternal(true)    // Example: block all internal IPs
    .build();

HttpClient httpClient = new HttpClient();
httpClient.setSocketAddressResolver(new JettyHttpClientDnsResolver(securityDnsHandler));

// Start the client before using it
// httpClient.start();

// Now use this httpClient to make requests
// httpClient.GET("http://example.com");

// Stop the client when done
// httpClient.stop();
```

### Using with Reactor Netty's HttpClient

To use the SSRF protection with Reactor Netty's `HttpClient`, you can configure it with `NettyHttpClientAddressSelector`:

```java
import reactor.netty.http.client.HttpClient;
import client.NettyHttpClientAddressSelector;
import client.dns.SecurityDnsHandler;

// ...

SecurityDnsHandler securityDnsHandler = SecurityDnsHandler.builder()
    .allowList("1.1.1.1", "8.8.8.8") // Example: only allow specific IPs
    .reportOnly(true)               // Example: log instead of blocking
    .build();

NettyHttpClientAddressSelector addressSelector = new NettyHttpClientAddressSelector(securityDnsHandler);

HttpClient httpClient = HttpClient.create()
    .resolvedAddressesSelector(addressSelector);

// Now use this httpClient to make requests
// httpClient.get().uri("http://example.com").response().block();
```

See `test/java/com/google/springframework/security/web/client/UsageExample.java` for more examples of `SecureRestTemplate`.
For `JettyHttpClientDnsResolver` and `NettyHttpClientAddressSelector`, refer to their respective test files for usage examples.
