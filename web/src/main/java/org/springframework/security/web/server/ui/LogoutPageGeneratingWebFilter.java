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
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * Generates a default log out page.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class LogoutPageGeneratingWebFilter implements WebFilter {

	private ServerWebExchangeMatcher matcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET, "/logout");

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
		String contextPath = exchange.getRequest().getPath().contextPath().value();
		return token.map(LogoutPageGeneratingWebFilter::csrfToken).defaultIfEmpty("").map((csrfTokenHtmlInput) -> {
			byte[] bytes = createPage(csrfTokenHtmlInput, contextPath);
			DataBufferFactory bufferFactory = exchange.getResponse().bufferFactory();
			return bufferFactory.wrap(bytes);
		});
	}

	private static byte[] createPage(String csrfTokenHtmlInput, String contextPath) {
		return HtmlTemplates.fromTemplate(LOGOUT_PAGE_TEMPLATE)
			.withValue("contextPath", contextPath)
			.withRawHtml("csrf", csrfTokenHtmlInput.indent(8))
			.render()
			.getBytes(Charset.defaultCharset());
	}

	private static String csrfToken(CsrfToken token) {
		return HtmlTemplates.fromTemplate(CSRF_INPUT_TEMPLATE)
			.withValue("name", token.getParameterName())
			.withValue("value", token.getToken())
			.render();
	}

	private static final String LOGOUT_PAGE_TEMPLATE = """
			<!DOCTYPE html>
			<html lang="en">
			  <head>
			    <meta charset="utf-8">
			    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
			    <meta name="description" content="">
			    <meta name="author" content="">
			    <title>Confirm Log Out?</title>
			    <link href="{{contextPath}}/default-ui.css" rel="stylesheet" />
			  </head>
			  <body>
			    <div class="content">
			      <form class="logout-form" method="post" action="{{contextPath}}/logout">
			        <h2>Are you sure you want to log out?</h2>
			{{csrf}}
			        <button class="primary" type="submit">Log Out</button>
			      </form>
			    </div>
			  </body>
			</html>""";

	private static final String CSRF_INPUT_TEMPLATE = """
			<input name="{{name}}" type="hidden" value="{{value}}" />
			""";

}
