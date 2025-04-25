package com.google.springframework.security.web.client;

import java.util.List;
import java.util.function.Function;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.client.RestTemplate;

public class Hc5ClientAdapter implements ClientAdapter {

	private Function<DnsResolver, ClientHttpRequestFactory> customBuilder = null;

	private Function<Registry<ConnectionSocketFactory>, HttpClientConnectionManager> customConnectionMgr = null;


	public Hc5ClientAdapter() {
	}

	public static Hc5ClientAdapter withCustomBuilder(Function<DnsResolver, ClientHttpRequestFactory> customBuilder) {
		Hc5ClientAdapter hc5ClientAdapter = new Hc5ClientAdapter();
		hc5ClientAdapter.customBuilder = customBuilder;
		return hc5ClientAdapter;
	}

	public Hc5ClientAdapter withConnectionManager(
			Function<Registry<ConnectionSocketFactory>, HttpClientConnectionManager> customConnectionMgr) {
		this.customConnectionMgr = customConnectionMgr;
		return this;
	}

	@Override
	public ClientHttpRequestFactory buildToHttpRequestFactory(List<SsrfProtectionFilter> filters,
			boolean reportOnly) {
		Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
				.register("http", PlainConnectionSocketFactory.getSocketFactory())
				.register("https", SSLConnectionSocketFactory.getSocketFactory()).build();

		Hc5SsrfDnsResolver hc5SsrfDnsResolver = new Hc5SsrfDnsResolver(filters, reportOnly);
		if (customBuilder != null) {
			return customBuilder.apply(hc5SsrfDnsResolver);
		}

		HttpClientConnectionManager connManager = null;
		if (customConnectionMgr != null) {
			connManager = customConnectionMgr.apply(registry);
		} else {
			connManager = PoolingHttpClientConnectionManagerBuilder.create().setDnsResolver(hc5SsrfDnsResolver).build();
		}

		// If connManager is null ( default ), this will use a PoolingHttpClientConnectionManager
		// This behaviour corresponds to the HttpComponentsClientHttpRequestFactory default.
		CloseableHttpClient httpClient = HttpClientBuilder.create().useSystemProperties()
				.setConnectionManager(connManager)
				.build();

		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(
				httpClient);
		return requestFactory;
	}

	@Override
	public RestTemplate buildRestTemplate(List<SsrfProtectionFilter> filters, boolean reportOnly) {
		return new RestTemplate(buildToHttpRequestFactory(filters, reportOnly));
	}

	@Override
	public ReactorClientHttpConnector buildToClientHttpConnector(List<SsrfProtectionFilter> filters,
			boolean reportOnly) {
		throw new UnsupportedOperationException();
	}
}
