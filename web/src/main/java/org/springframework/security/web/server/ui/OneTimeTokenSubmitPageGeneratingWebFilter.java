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

package org.springframework.security.web.server.ui;

import java.nio.charset.Charset;

import reactor.core.publisher.Mono;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * Creates a default one-time token submit page. If the request contains a {@code token}
 * query param the page will automatically fill the form with the token value.
 *
 * @author Max Batischev
 * @since 6.4
 */
public final class OneTimeTokenSubmitPageGeneratingWebFilter implements WebFilter {

	private ServerWebExchangeMatcher matcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/login/ott");

	private String loginProcessingUrl = "/login/ott";

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.matcher.matches(exchange)
			.filter(ServerWebExchangeMatcher.MatchResult::isMatch)
			.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
			.flatMap((matchResult) -> render(exchange));
	}

	private Mono<Void> render(ServerWebExchange exchange) {
		ServerHttpResponse result = exchange.getResponse();
		result.setStatusCode(HttpStatus.OK);
		result.getHeaders().setContentType(MediaType.TEXT_HTML);
		return result.writeWith(createBuffer(exchange));
	}

	private Mono<DataBuffer> createBuffer(ServerWebExchange exchange) {
		Mono<CsrfToken> token = exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
		return token.map(OneTimeTokenSubmitPageGeneratingWebFilter::csrfToken)
			.defaultIfEmpty("")
			.map((csrfTokenHtmlInput) -> {
				byte[] bytes = createPage(exchange, csrfTokenHtmlInput);
				DataBufferFactory bufferFactory = exchange.getResponse().bufferFactory();
				return bufferFactory.wrap(bytes);
			});
	}

	private byte[] createPage(ServerWebExchange exchange, String csrfTokenHtmlInput) {
		MultiValueMap<String, String> queryParams = exchange.getRequest().getQueryParams();
		String token = queryParams.getFirst("token");
		String tokenValue = StringUtils.hasText(token) ? token : "";

		String contextPath = exchange.getRequest().getPath().contextPath().value();

		return HtmlTemplates.fromTemplate(ONE_TIME_TOKEN_SUBMIT_PAGE_TEMPLATE)
			.withRawHtml("contextPath", contextPath)
			.withValue("tokenValue", tokenValue)
			.withRawHtml("csrf", csrfTokenHtmlInput.indent(8))
			.withValue("loginProcessingUrl", contextPath + this.loginProcessingUrl)
			.render()
			.getBytes(Charset.defaultCharset());
	}

	private static String csrfToken(CsrfToken token) {
		return HtmlTemplates.fromTemplate(CSRF_INPUT_TEMPLATE)
			.withValue("name", token.getParameterName())
			.withValue("value", token.getToken())
			.render();
	}

	/**
	 * Use this {@link ServerWebExchangeMatcher} to choose whether this filter will handle
	 * the request. By default, it handles {@code /login/ott}.
	 * @param requestMatcher {@link ServerWebExchangeMatcher} to use
	 */
	public void setRequestMatcher(ServerWebExchangeMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.matcher = requestMatcher;
	}

	/**
	 * Specifies the URL that the submit form should POST to. Defaults to
	 * {@code /login/ott}.
	 * @param loginProcessingUrl
	 */
	public void setLoginProcessingUrl(String loginProcessingUrl) {
		Assert.hasText(loginProcessingUrl, "loginProcessingUrl cannot be null or empty");
		this.loginProcessingUrl = loginProcessingUrl;
	}

	private static final String ONE_TIME_TOKEN_SUBMIT_PAGE_TEMPLATE = """
			<!DOCTYPE html>
			<html lang="en">
			  <head>
			    <title>One-Time Token Login</title>
			    <meta charset="utf-8"/>
			    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"/>
			    <link href="{{contextPath}}/default-ui.css" rel="stylesheet" />
			  </head>
			  <body>
			    <div class="container">
			      <form class="login-form" action="{{loginProcessingUrl}}" method="post">
			        <h2>Please input the token</h2>
			        <p>
			          <label for="token" class="screenreader">Token</label>
			          <input type="text" id="token" name="token" value="{{tokenValue}}" placeholder="Token" required="true" autofocus="autofocus"/>
			        </p>
			{{csrf}}
			        <button class="primary" type="submit">Sign in</button>
			      </form>
			    </div>
			  </body>
			</html>
			""";

	private static final String CSRF_INPUT_TEMPLATE = """
			<input name="{{name}}" type="hidden" value="{{value}}" />
			""";

}
