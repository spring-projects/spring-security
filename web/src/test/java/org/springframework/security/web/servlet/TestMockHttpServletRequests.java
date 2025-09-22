/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.servlet;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

public final class TestMockHttpServletRequests {

	private TestMockHttpServletRequests() {

	}

	public static Builder get() {
		return new Builder(HttpMethod.GET);
	}

	public static Builder get(String url) {
		return get().applyUrl(url);
	}

	public static Builder post() {
		return new Builder(HttpMethod.POST);
	}

	public static Builder post(String url) {
		return post().applyUrl(url);
	}

	public static Builder request(String method) {
		return new Builder(HttpMethod.valueOf(method));
	}

	public static final class Builder {

		private static final Pattern URL = Pattern.compile("((?<scheme>https?)://)?"
				+ "((?<hostname>[^:/]+)(:(?<port>\\d+))?)?" + "(?<path>[^?]+)?" + "(\\?(?<query>.*))?");

		private final HttpMethod method;

		private String requestUri;

		private final Map<String, String> parameters = new LinkedHashMap<>();

		private String scheme = MockHttpServletRequest.DEFAULT_SCHEME;

		private int port = MockHttpServletRequest.DEFAULT_SERVER_PORT;

		private String hostname = MockHttpServletRequest.DEFAULT_SERVER_NAME;

		private String contextPath;

		private String servletPath;

		private String pathInfo;

		private String queryString;

		private Builder(HttpMethod method) {
			this.method = method;
		}

		private Builder applyUrl(String url) {
			Matcher matcher = URL.matcher(url);
			if (matcher.matches()) {
				applyElement(this::scheme, matcher.group("scheme"));
				applyElement(this::port, matcher.group("port"));
				applyElement(this::serverName, matcher.group("hostname"));
				applyElement(this::requestUri, matcher.group("path"));
				applyElement(this::queryString, matcher.group("query"));
			}
			return this;
		}

		private <T> void applyElement(Consumer<T> apply, T value) {
			if (value != null) {
				apply.accept(value);
			}
		}

		public Builder requestUri(String contextPath, String servletPath, String pathInfo) {
			this.contextPath = contextPath;
			this.servletPath = servletPath;
			this.pathInfo = pathInfo;
			this.requestUri = Stream.of(contextPath, servletPath, pathInfo)
				.filter(StringUtils::hasText)
				.collect(Collectors.joining());
			return this;
		}

		public Builder requestUri(String requestUri) {
			return requestUri(null, requestUri, null);
		}

		public Builder param(String name, String value) {
			this.parameters.put(name, value);
			return this;
		}

		private Builder port(String port) {
			if (port != null) {
				this.port = Integer.parseInt(port);
			}
			return this;
		}

		public Builder port(int port) {
			this.port = port;
			return this;
		}

		public Builder queryString(String queryString) {
			this.queryString = queryString;
			return this;
		}

		public Builder scheme(String scheme) {
			this.scheme = scheme;
			return this;
		}

		public Builder serverName(String serverName) {
			this.hostname = serverName;
			return this;
		}

		public MockHttpServletRequest build() {
			MockHttpServletRequest request = new MockHttpServletRequest();
			Map<String, List<String>> params = UriComponentsBuilder.fromUriString("?" + this.queryString)
				.build()
				.getQueryParams();
			for (Map.Entry<String, List<String>> entry : params.entrySet()) {
				for (String value : entry.getValue()) {
					request.addParameter(entry.getKey(), value);
				}
			}
			applyElement(request::setContextPath, this.contextPath);
			applyElement(request::setContextPath, this.contextPath);
			applyElement(request::setMethod, this.method.name());
			applyElement(request::setParameters, this.parameters);
			applyElement(request::setPathInfo, this.pathInfo);
			applyElement(request::setServletPath, this.servletPath);
			applyElement(request::setScheme, this.scheme);
			applyElement(request::setServerPort, this.port);
			applyElement(request::setServerName, this.hostname);
			applyElement(request::setQueryString, this.queryString);
			applyElement(request::setRequestURI, this.requestUri);
			request.setSecure("https".equals(this.scheme));
			return request;
		}

	}

}
