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

public class SecureRestTemplate {

	/**
	 * Helper enum to make configuring with system properties easier
	 */
	private enum ProtectionMode {
		ALLOW_LIST, DENY_LIST, BLOCK_EXTERNAL, BLOCK_INTERNAL,
	}

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

	public static class Builder {

		private List<SsrfProtectionFilter> customFilters = new ArrayList<>();

		// Only one of the two can be used at the same time
		private List<String> ipAllowList = new ArrayList<>();
		private List<String> ipBlockList = new ArrayList<>();
		private boolean isReportOnly = false;
		private NetworkMode networkMode = null;
		private ClientType clientType = ClientType.HTTP_CLIENT_5;

		public Builder reportOnly(boolean isReportOnly) {
			this.isReportOnly = isReportOnly;
			return this;
		}

		public Builder networkMode(NetworkMode mode) {
			this.networkMode = mode;
			return this;
		}

		public Builder withAllowlist(String... ipList) {
			this.ipAllowList.addAll(List.of(ipList));
			return this;
		}

		public Builder withAllowlist(Iterable<String> ipList) {
			ipList.forEach(this.ipAllowList::add);
			return this;
		}

		public Builder withBlocklist(String... ipList) {
			this.ipBlockList.addAll(List.of(ipList));
			return this;
		}

		public Builder withBlocklist(Iterable<String> ipList) {
			ipList.forEach(this.ipBlockList::add);
			return this;
		}


		public Builder withCustomFilter(SsrfProtectionFilter filter) {
			this.customFilters.add(filter);
			return this;
		}

		public Builder withClient(ClientType clientType) {
			this.clientType = clientType;
			return this;
		}

		private RestTemplate buildHttpClient5(SsrfDnsResolver dnsResolver) {

			Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
					.register("http", PlainConnectionSocketFactory.getSocketFactory())
					.register("https", SSLConnectionSocketFactory.getSocketFactory()).build();

			BasicHttpClientConnectionManager connManager = new BasicHttpClientConnectionManager(registry, null, null,
					dnsResolver);

			CloseableHttpClient httpClient = HttpClientBuilder.create().setConnectionManager(connManager).build();

			HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(
					httpClient);
			return new RestTemplate(requestFactory);
		}

		public RestTemplate build() {
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
				filters.add(new ListedSsrfProtectionFilter(ipAllowList.stream().map(IpOrRange::new).collect(toList()),
						FilterMode.BLOCK_LIST));
			}

			filters.addAll(customFilters);

			SsrfDnsResolver dnsResolver = new SsrfDnsResolver(filters, isReportOnly);

			if (this.clientType == ClientType.HTTP_CLIENT_5) {
				return buildHttpClient5(dnsResolver);
			} else {
				throw new IllegalArgumentException("Only HTTP_CLIENT_5 backed RestTemplates are supported for now");
			}
		}
	}
}
