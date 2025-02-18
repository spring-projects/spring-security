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

import static java.util.stream.Collectors.toList;

import com.google.springframework.security.web.client.ListedSsrfProtectionFilter.FilterMode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.config.Registry;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.util.SocketAddressResolver;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.JettyClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

/**
 * SecureRestTemplate provides a way to create a RestTemplate which protects against unintentional network access and
 * provides mitigations against Server Side Resource Forgery via DNS rebinding. Use the associated
 * {@link com.google.springframework.security.web.client.SecureRestTemplate.Builder} to create new instances, it also
 * provides a method to create the underlying  {@link org.springframework.http.client.ClientHttpRequestFactory}.
 * Currently two flavours are supported, backed by Apache HttpClient 5 or Jetty.
 */
public class SecureRestTemplate {

	/**
	 * Helper enum to make configuring with system properties easier, when using {@link #buildDefault()}
	 *
	 * @see #ALLOW_LIST
	 * @see #DENY_LIST
	 * @see #BLOCK_EXTERNAL
	 * @see #BLOCK_INTERNAL
	 */
	private enum ProtectionMode {
		/**
		 * Use the <b>ssrf.protection.iplist</b> property in {@link #buildDefault()} as an allow-list.
		 */
		ALLOW_LIST,
		/**
		 * Use the <b>ssrf.protection.iplist</b> property in {@link #buildDefault()} as a deny-list.
		 */
		DENY_LIST,

		/**
		 * Block requests directed towards the non-local, non-loopback addresses.
		 */
		BLOCK_EXTERNAL,

		/**
		 * Block requests directed towards the local or loopback addresses.
		 */
		BLOCK_INTERNAL,
	}

	/**
	 * Build {@link com.google.springframework.security.web.client.SecureRestTemplate} based on JVM global system
	 * properties. The following properties can be used to configured:
	 * <ul>
	 *     <li><b>ssrf.protection.mode</b></li> Mandatory property to specify
	 *     {@link com.google.springframework.security.web.client.SecureRestTemplate.ProtectionMode} if you would like to use this method.
	 *     <li><b>ssrf.protection.iplist</b></li>
	 *     The list of ip addresses or hostnames to use for allow-listing/block-listing based on the property above when it's set to
	 *      <b>ALLOW_LIST</b> or <b>DENY_LIST</b>.
	 *     <li><b>ssrf.protection.report_only</b></li> If set, request are not blocked just logged. Only the existence of the property is checked, the value is ignored.
	 *
	 * </ul>
	 */

	public static RestTemplate buildDefault() {

		String modeProperty = System.getProperty("ssrf.protection.mode");

		SsrfProtectionFilter filter = null;

		if (modeProperty == null) {
			throw new IllegalStateException("ssrf.protection.mode is not set but defaultFilter() requested");
		}
		ProtectionMode mode = ProtectionMode.valueOf(modeProperty.toUpperCase());

		boolean reportOnly = System.getProperty("ssrf.protection.report_only") != null;

		if (mode == ProtectionMode.ALLOW_LIST || mode == ProtectionMode.DENY_LIST) {
			String ipList = System.getProperty("ssrf.protection.iplist");
			if (ipList == null) {
				throw new IllegalStateException(
						"ssrf.protection.iplist is required for ALLOW_LIST or DENY_LIST modes in comma separated CIDR format");
			}
			FilterMode filterMode = (mode == ProtectionMode.ALLOW_LIST ? FilterMode.ALLOW_LIST : FilterMode.BLOCK_LIST);
			filter = new ListedSsrfProtectionFilter(
					Arrays.stream(ipList.strip().split(",")).map(IpOrRange::new).toList(), filterMode);
		} else if (mode == ProtectionMode.BLOCK_INTERNAL || mode == ProtectionMode.BLOCK_EXTERNAL) {
			NetworkMode filterMode = (mode == ProtectionMode.BLOCK_INTERNAL ? NetworkMode.BLOCK_INTERNAL
					: NetworkMode.BLOCK_EXTERNAL);

			filter = new BasicSsrfProtectionFilter(filterMode);
		}

		return new Builder().reportOnly(reportOnly).withCustomFilter(filter).build();


	}

	/**
	 * Builder class to create a  {@link com.google.springframework.security.web.client.SecureRestTemplate} or an
	 * underlying {@link org.springframework.http.client.ClientHttpRequestFactory}. It also exposes ways to create the
	 * underlying DNS-resolvers which contain the heart of the protection logic.
	 */
	public static class Builder {

		private List<SsrfProtectionFilter> customFilters = new ArrayList<>();

		// Only one of the two can be used at the same time
		private List<String> ipAllowList = new ArrayList<>();
		private List<String> ipBlockList = new ArrayList<>();
		private boolean isReportOnly = false;
		private NetworkMode networkMode = null;

		// Currently redundant due to changes around using a Jetty client.
		// Keeping it for future use when more client types are added.
		private ClientType clientType = ClientType.HTTP_CLIENT_5;
		private HttpClient jettyClient = null;

		/**
		 * Create a {@link com.google.springframework.security.web.client.SecureRestTemplate} with a
		 * {@link org.eclipse.jetty.client.HttpClient} to use to make the requests. The lifetime of a
		 * {@link org.eclipse.jetty.client.HttpClient} should be handled by Spring (or manually)
		 * {@see UsageExample.java}
		 *
		 * @param jettyClient the HttpClient to use
		 */

		public Builder fromJettyClient(HttpClient jettyClient) {
			this.jettyClient = jettyClient;
			this.clientType = ClientType.JETTY_CLIENT;
			return this;
		}

		/**
		 * When set to true rule violating requests are not blocked only logged.
		 */
		public Builder reportOnly(boolean isReportOnly) {
			this.isReportOnly = isReportOnly;
			return this;
		}

		/**
		 * Set mode do block requests towards the internet or block requests towards the internet.
		 */
		public Builder networkMode(NetworkMode networkMode) {
			this.networkMode = networkMode;
			return this;
		}

		/**
		 * List of ip-addresses or hostnames to use in an allow-list.
		 */
		public Builder withAllowlist(String... ipList) {
			ipAllowList.addAll(List.of(ipList));
			return this;
		}

		/**
		 * List of ip-addresses or hostnames to use in an allow-list.
		 */
		public Builder withAllowlist(Iterable<String> ipList) {
			ipList.forEach(ipAllowList::add);
			return this;
		}


		/**
		 * List of ip-addresses or hostnames to use in an block-list.
		 */
		public Builder withBlocklist(String... ipList) {
			ipBlockList.addAll(List.of(ipList));
			return this;
		}

		/**
		 * List of ip-addresses or hostnames to use in an block-list.
		 */
		public Builder withBlocklist(Iterable<String> ipList) {
			ipList.forEach(ipBlockList::add);
			return this;
		}

		/**
		 * When very specific criteria are needed to block or allow a request a custom
		 * {@link com.google.springframework.security.web.client.SsrfProtectionFilter} implementation can be plugged
		 * in.
		 */
		public Builder withCustomFilter(SsrfProtectionFilter filter) {
			customFilters.add(filter);
			return this;
		}

		// Reserved for future use, when adding more ClientTypes
		// Currently HC5 is the default and Jetty Client needs to be externally provided
		// because of cleanup issues
		private Builder withClient(ClientType clientType) {
			if (clientType == ClientType.JETTY_CLIENT) {
				throw new IllegalStateException(
						"The Builder was created from a Jetty HttpClient. Cannot change ClientType.");
			}

			this.clientType = clientType;
			return this;
		}

		private ClientHttpRequestFactory makeHttpClient5(HcSsrfDnsResolver dnsResolver) {

			Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
					.register("http", PlainConnectionSocketFactory.getSocketFactory())
					.register("https", SSLConnectionSocketFactory.getSocketFactory()).build();

			BasicHttpClientConnectionManager connManager = new BasicHttpClientConnectionManager(registry, null, null,
					dnsResolver);

			CloseableHttpClient httpClient = HttpClientBuilder.create().setConnectionManager(connManager).build();

			HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(
					httpClient);
			return requestFactory;
		}

		private ClientHttpRequestFactory makeJettyClient(JettySsrfDnsResolver dnsResolver) {
			jettyClient.setSocketAddressResolver(dnsResolver);
			JettyClientHttpRequestFactory requestFactory = new JettyClientHttpRequestFactory(jettyClient);
			return requestFactory;
		}

		private List<SsrfProtectionFilter> makeFilters() {
			List<SsrfProtectionFilter> filters = new ArrayList<>();

			if (ipAllowList.size() != 0 && ipBlockList.size() != 0) {
				throw new IllegalArgumentException(
						"Logic inconsistency: ipBlockList and -AllowList can not be used at the same time");
			}

			if (networkMode != null) {
				filters.add(new BasicSsrfProtectionFilter(networkMode));
			}

			if (ipAllowList.size() > 0) {
				filters.add(new ListedSsrfProtectionFilter(ipAllowList.stream().map(IpOrRange::new).collect(toList()),
						FilterMode.ALLOW_LIST));
			}
			if (ipBlockList.size() > 0) {
				filters.add(new ListedSsrfProtectionFilter(ipBlockList.stream().map(IpOrRange::new).collect(toList()),
						FilterMode.BLOCK_LIST));
			}

			filters.addAll(customFilters);
			return filters;
		}

		/**
		 * Helper method to create the Jetty specific DNS resolver used in an underlying
		 * {@link org.eclipse.jetty.client.HttpClient} for request filtering.
		 *
		 * @return the custom resolver which implements the filtering and DNS rebinding protection logic.
		 */
		public SocketAddressResolver buildToJettyResolver() {
			return new JettySsrfDnsResolver(makeFilters(), isReportOnly);
		}

		/**
		 * Helper method to create the DNS resolver used in an underlying
		 * {@link org.apache.hc.client5.http.impl.classic.CloseableHttpClient} for request filtering.
		 *
		 * @return the custom resolver which implements the filtering and DNS rebinding protection logic.
		 */
		public DnsResolver buildToHttpClientDnsResolver() {
			return new HcSsrfDnsResolver(makeFilters(), isReportOnly);
		}

		/**
		 * Helper method to create a {@link org.springframework.http.client.ClientHttpRequestFactory} for more
		 * customization before creating a RestTemplate or RestClient.
		 */
		public ClientHttpRequestFactory buildToHttpRequestFactory() {
			if (clientType == ClientType.HTTP_CLIENT_5) {
				return makeHttpClient5(new HcSsrfDnsResolver(makeFilters(), isReportOnly));
			} else if (clientType == ClientType.JETTY_CLIENT) {
				jettyClient.setSocketAddressResolver(new JettySsrfDnsResolver(makeFilters(), isReportOnly));
				return new JettyClientHttpRequestFactory(jettyClient);
			} else {
				throw new IllegalArgumentException(
						"Only HTTP_CLIENT_5 and Jetty backed RestTemplates are supported for now");
			}
		}

		/**
		 * Create the {@link com.google.springframework.security.web.client.SecureRestTemplate} configured by this
		 * builder.
		 */
		public RestTemplate build() {
			if (clientType == ClientType.HTTP_CLIENT_5) {
				return new RestTemplate(makeHttpClient5(new HcSsrfDnsResolver(makeFilters(), isReportOnly)));
			} else if (clientType == ClientType.JETTY_CLIENT) {
				return new RestTemplate(makeJettyClient(new JettySsrfDnsResolver(makeFilters(), isReportOnly)));
			} else {
				throw new IllegalArgumentException(
						"Only HTTP_CLIENT_5 and Jetty backed RestTemplates are supported for now");
			}
		}
	}
}
