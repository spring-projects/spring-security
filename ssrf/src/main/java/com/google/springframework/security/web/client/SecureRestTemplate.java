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
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.util.ClassUtils;
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

	private static final boolean hc5Present;

	static {
		ClassLoader classLoader = RestTemplate.class.getClassLoader();
		hc5Present = ClassUtils.isPresent("org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager",
				classLoader);
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

		private ClientType clientType = ClientType.HTTP_CLIENT_5;

		private ClientAdapter clientAdapter = null;

		/**
		 * Create a {@link com.google.springframework.security.web.client.SecureRestTemplate} by using a Jetty client.
		 *
		 * {@see UsageExample.java}
		 *
		 * @param jettyClient a {@link JettyClientAdapter} should be used here
		 */
		public Builder fromJettyClient(ClientAdapter jettyClient) {
			// TODO(vaspori): make sure clientType and adapter are consistent or remove clientType
			this.clientType = ClientType.JETTY_CLIENT;
			this.clientAdapter = jettyClient;
			return this;
		}


		/**
		 * Create a {@link com.google.springframework.security.web.client.SecureRestTemplate} by using a Netty client.
		 *
		 * {@see UsageExample.java}
		 *
		 * @param nettyClient a {@link NettyClientAdapter} should be used here
		 */
		public Builder fromNettyClient(ClientAdapter nettyClient) {
			this.clientType = ClientType.NETTY_CLIENT;
			this.clientAdapter = nettyClient;
			return this;
		}

		/**
		 * Create a {@link com.google.springframework.security.web.client.SecureRestTemplate} by using a Apache
		 * HttpClient . {@link Hc5ClientAdapter} makes it also possible to customize the parameters of the underlying
		 * client: {@see UsageExample.java}
		 *
		 * @param hc5Client a {@link Hc5ClientAdapter} should be used here
		 */
		public Builder fromApacheClient(ClientAdapter hc5Client) {
			this.clientType = ClientType.HTTP_CLIENT_5;
			this.clientAdapter = hc5Client;
			return this;
		}

		/**
		 * Create a default Builder, an Apache HttpClient will be used as a default. If the library is not in the
		 * classpath, the {@see build()} method will throw a RuntimeException().
		 */
		public Builder() {
			this.clientType = ClientType.HTTP_CLIENT_5;

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

		private void checkDependencies() {
			if (clientType == ClientType.HTTP_CLIENT_5 && clientAdapter == null) {
				if (SecureRestTemplate.hc5Present) {
					try {
						Class<?> aClass = Class.forName(
								"com.google.springframework.security.web.client.Hc5ClientAdapter");
						this.clientAdapter = (ClientAdapter) aClass.getDeclaredConstructor().newInstance();
					} catch (Exception e) {
						throw new RuntimeException(e);
					}
				} else {
					throw new RuntimeException(
							"Dependency org.apache.httpcomponents.client5:httpclient5 required for this RestTemplate");
				}
			}

		}

		public ClientHttpConnector buildToClientHttpConnector() {
			if (clientType != ClientType.NETTY_CLIENT) {
				throw new IllegalStateException("buildToClientHttpConnector() can only be used with NETTY_CLIENT.");
			}
			return clientAdapter.buildToClientHttpConnector(makeFilters(), isReportOnly);
		}


		/**
		 * Helper method to create a {@link org.springframework.http.client.ClientHttpRequestFactory} for more
		 * customization before creating a RestTemplate or RestClient.
		 */
		public ClientHttpRequestFactory buildToHttpRequestFactory() {
			checkDependencies();
			return this.clientAdapter.buildToHttpRequestFactory(makeFilters(), isReportOnly);
		}

		/**
		 * Create the {@link com.google.springframework.security.web.client.SecureRestTemplate} configured by this
		 * builder.
		 */
		public RestTemplate build() {
			checkDependencies();
			return this.clientAdapter.buildRestTemplate(makeFilters(), isReportOnly);
		}
	}
}
