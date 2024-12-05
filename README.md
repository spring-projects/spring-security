# SSRF Protected `RestTemplate` Library

This library provides a framework for preventing Server-Side Request Forgery (SSRF) vulnerabilities in Java applications. It allows you to define and enforce rules for restricting which hosts, IP addresses and address ranges can be accessed by your application.

## Features

* **Flexible filtering:** Supports different filtering modes, including:
    * **Basic filtering:** Allow or block internal/external IP addresses.
    * **List-based filtering:** Allow or block specific IP addresses and ranges.
* **Customizable:** Easily integrate with your existing DNS resolution mechanism.
* **Extensible:**  Create your own custom filters to implement specific SSRF protection logic.

## Limitations

This is the first iteration of the library. Currently the `RestTemplate` is backed by an Apache Commons 5 HttpClient.

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

See `test/java/com/google/springframework/security/web/client/UsageExample.java` for more examples
