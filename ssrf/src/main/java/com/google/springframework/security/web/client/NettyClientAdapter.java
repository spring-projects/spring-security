package com.google.springframework.security.web.client;

import java.util.List;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ReactorNettyClientRequestFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.client.RestTemplate;
import reactor.netty.http.client.HttpClient;

public class NettyClientAdapter implements ClientAdapter {

	private HttpClient nettyClient;

	public NettyClientAdapter(HttpClient nettyClient) {
		this.nettyClient = nettyClient;
	}

	@Override
	public ClientHttpRequestFactory buildToHttpRequestFactory(List<SsrfProtectionFilter> filters,
			boolean reportOnly) {
		NettySsrfDnsResolver nettyResolver = new NettySsrfDnsResolver(filters, reportOnly);
		return new ReactorNettyClientRequestFactory(nettyClient.resolver(nettyResolver));
	}

	@Override
	public RestTemplate buildRestTemplate(List<SsrfProtectionFilter> filters, boolean reportOnly) {

		return new RestTemplate(buildToHttpRequestFactory(filters, reportOnly));
	}

	public ReactorClientHttpConnector buildToClientHttpConnector(List<SsrfProtectionFilter> filters,
			boolean reportOnly) {
		NettySsrfDnsResolver nettyResolver = new NettySsrfDnsResolver(filters, reportOnly);
		return new ReactorClientHttpConnector(nettyClient.resolver(nettyResolver));

	}

}
