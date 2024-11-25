/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.springframework.security.web.client;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

public class SecureRestTemplateUtil {

	static RestTemplate buildWithResolver(SsrfDnsResolver dnsResolver) {
		Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
				.register("http", PlainConnectionSocketFactory.getSocketFactory())
				.register("https", SSLConnectionSocketFactory.getSocketFactory())
				.build();

		BasicHttpClientConnectionManager connManager = new BasicHttpClientConnectionManager(
				registry, null, null, dnsResolver);

		CloseableHttpClient httpClient = HttpClientBuilder.create()
				.setConnectionManager(connManager)
				.build();

		HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
		return new RestTemplate(requestFactory);
	}

	public static RestTemplate makeSecureHC5Template(SsrfProtectionConfig config) {
		SsrfDnsResolver dnsResolver = new SsrfDnsResolver(config);
		return buildWithResolver(dnsResolver);
	}

	public static RestTemplate makeHC5Default() {
		SsrfDnsResolver dnsResolver = new SsrfDnsResolver(SsrfProtectionConfig.defaultFilter());
		return buildWithResolver(dnsResolver);
	}

}
