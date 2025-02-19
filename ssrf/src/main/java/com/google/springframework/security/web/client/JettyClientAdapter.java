package com.google.springframework.security.web.client;

import java.util.List;
import org.eclipse.jetty.client.HttpClient;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.JettyClientHttpRequestFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.client.RestTemplate;

public class JettyClientAdapter implements ClientAdapter {

	private HttpClient jettyClient = null;

	private ClientHttpRequestFactory makeJettyClient(JettySsrfDnsResolver dnsResolver) {
		jettyClient.setSocketAddressResolver(dnsResolver);
		JettyClientHttpRequestFactory requestFactory = new JettyClientHttpRequestFactory(jettyClient);
		return requestFactory;
	}

	public JettyClientAdapter(HttpClient jettyClient) {
		this.jettyClient = jettyClient;
	}

	public RestTemplate buildRestTemplate(List<SsrfProtectionFilter> filters, boolean reportOnly) {
		return new RestTemplate(makeJettyClient(new JettySsrfDnsResolver(filters, reportOnly)));
	}

	@Override
	public ReactorClientHttpConnector buildToClientHttpConnector(List<SsrfProtectionFilter> filters,
			boolean reportOnly) {
		throw new UnsupportedOperationException();
	}

	public ClientHttpRequestFactory buildToHttpRequestFactory(List<SsrfProtectionFilter> filters, boolean reportOnly) {
		jettyClient.setSocketAddressResolver(new JettySsrfDnsResolver(filters, reportOnly));
		return new JettyClientHttpRequestFactory(jettyClient);

	}


}
