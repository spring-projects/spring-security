/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.htmlunit.server;

import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import com.gargoylesoftware.htmlunit.FormEncodingType;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.util.NameValuePair;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.lang.Nullable;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;

final class HtmlUnitWebTestClient {

	private final WebClient webClient;

	private final WebTestClient webTestClient;

	HtmlUnitWebTestClient(WebClient webClient, WebTestClient webTestClient) {
		Assert.notNull(webClient, "WebClient must not be null");
		Assert.notNull(webTestClient, "WebTestClient must not be null");
		this.webClient = webClient;
		this.webTestClient = webTestClient.mutate().filter(new FollowRedirects()).filter(new CookieManager()).build();
	}

	public FluxExchangeResult<String> getResponse(WebRequest webRequest) {
		WebTestClient.RequestBodySpec request = this.webTestClient.method(httpMethod(webRequest)).uri(uri(webRequest));
		contentType(request, webRequest);
		cookies(request, webRequest);
		headers(request, webRequest);

		return content(request, webRequest).exchange().returnResult(String.class);
	}

	private WebTestClient.RequestHeadersSpec<?> content(WebTestClient.RequestBodySpec request, WebRequest webRequest) {
		String requestBody = webRequest.getRequestBody();
		if (requestBody == null) {
			List<NameValuePair> params = webRequest.getRequestParameters();
			if (params != null && !params.isEmpty()) {
				return request.body(BodyInserters.fromFormData(formData(params)));
			}
			return request;
		}
		return request.body(BodyInserters.fromObject(requestBody));
	}

	private MultiValueMap<String, String> formData(List<NameValuePair> params) {
		MultiValueMap<String, String> result = new LinkedMultiValueMap<>(params.size());
		params.forEach((pair) -> result.add(pair.getName(), pair.getValue()));
		return result;
	}

	private void contentType(WebTestClient.RequestBodySpec request, WebRequest webRequest) {
		String contentType = header("Content-Type", webRequest);
		if (contentType == null) {
			FormEncodingType encodingType = webRequest.getEncodingType();
			if (encodingType != null) {
				contentType = encodingType.getName();
			}
		}
		MediaType mediaType = contentType == null ? MediaType.ALL : MediaType.parseMediaType(contentType);
		request.contentType(mediaType);
	}

	private void cookies(WebTestClient.RequestBodySpec request, WebRequest webRequest) {
		String cookieHeaderValue = header("Cookie", webRequest);
		if (cookieHeaderValue != null) {
			StringTokenizer tokens = new StringTokenizer(cookieHeaderValue, "=;");
			while (tokens.hasMoreTokens()) {
				String cookieName = tokens.nextToken().trim();
				Assert.isTrue(tokens.hasMoreTokens(), () -> "Expected value for cookie name '" + cookieName
						+ "': full cookie header was [" + cookieHeaderValue + "]");
				String cookieValue = tokens.nextToken().trim();
				request.cookie(cookieName, cookieValue);
			}
		}

		Set<com.gargoylesoftware.htmlunit.util.Cookie> managedCookies = this.webClient.getCookies(webRequest.getUrl());
		for (com.gargoylesoftware.htmlunit.util.Cookie cookie : managedCookies) {
			request.cookie(cookie.getName(), cookie.getValue());
		}
	}

	@Nullable
	private String header(String headerName, WebRequest webRequest) {
		return webRequest.getAdditionalHeaders().get(headerName);
	}

	private void headers(WebTestClient.RequestBodySpec request, WebRequest webRequest) {
		webRequest.getAdditionalHeaders().forEach((name, value) -> request.header(name, value));
	}

	private HttpMethod httpMethod(WebRequest webRequest) {
		String httpMethod = webRequest.getHttpMethod().name();
		return HttpMethod.valueOf(httpMethod);
	}

	private URI uri(WebRequest webRequest) {
		URL url = webRequest.getUrl();
		return URI.create(url.toExternalForm());
	}

	static class FollowRedirects implements ExchangeFilterFunction {

		@Override
		public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
			return next.exchange(request).flatMap((response) -> redirectIfNecessary(request, next, response));
		}

		private Mono<ClientResponse> redirectIfNecessary(ClientRequest request, ExchangeFunction next,
				ClientResponse response) {
			URI location = response.headers().asHttpHeaders().getLocation();
			String host = request.url().getHost();
			String scheme = request.url().getScheme();
			if (location != null) {
				String redirectUrl = location.toASCIIString();
				if (location.getHost() == null) {
					redirectUrl = scheme + "://" + host + location.toASCIIString();
				}
				ClientRequest redirect = ClientRequest.method(HttpMethod.GET, URI.create(redirectUrl))
						.headers((headers) -> headers.addAll(request.headers()))
						.cookies((cookies) -> cookies.addAll(request.cookies()))
						.attributes((attributes) -> attributes.putAll(request.attributes())).build();

				return next.exchange(redirect).flatMap((r) -> redirectIfNecessary(request, next, r));
			}

			return Mono.just(response);
		}

	}

	static class CookieManager implements ExchangeFilterFunction {

		private Map<String, ResponseCookie> cookies = new HashMap<>();

		@Override
		public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
			return next.exchange(withClientCookies(request)).doOnSuccess((response) -> {
				response.cookies().values().forEach((cookies) -> {
					cookies.forEach((cookie) -> {
						if (cookie.getMaxAge().isZero()) {
							this.cookies.remove(cookie.getName());
						}
						else {
							this.cookies.put(cookie.getName(), cookie);
						}
					});
				});
			});
		}

		private ClientRequest withClientCookies(ClientRequest request) {
			return ClientRequest.from(request).cookies((c) -> c.addAll(clientCookies())).build();
		}

		private MultiValueMap<String, String> clientCookies() {
			MultiValueMap<String, String> result = new LinkedMultiValueMap<>(this.cookies.size());
			this.cookies.values().forEach((cookie) -> result.add(cookie.getName(), cookie.getValue()));
			return result;
		}

	}

}
