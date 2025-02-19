package com.google.springframework.security.web.client;

import java.util.List;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.client.RestTemplate;


/**
 * This interface is used to abstract away the underlying HTTP Client utilized for fetching the data.
 */
public interface ClientAdapter {

	ClientHttpRequestFactory buildToHttpRequestFactory(List<SsrfProtectionFilter> filters, boolean reportOnly);

	RestTemplate buildRestTemplate(List<SsrfProtectionFilter> filters, boolean reportOnly);

	ReactorClientHttpConnector buildToClientHttpConnector(List<SsrfProtectionFilter> filters, boolean reportOnly);
}
