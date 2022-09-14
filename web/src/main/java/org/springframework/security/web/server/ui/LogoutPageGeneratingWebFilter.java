/*
 * Copyright 2002-2022 the original author or authors.
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
		return this.matcher.matches(exchange).filter(ServerWebExchangeMatcher.MatchResult::isMatch)
				.switchIfEmpty(chain.filter(exchange).then(Mono.empty())).flatMap((matchResult) -> render(exchange));
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
		StringBuilder page = new StringBuilder();
		page.append("<!DOCTYPE html>\n");
		page.append("<html lang=\"en\">\n");
		page.append("  <head>\n");
		page.append("    <meta charset=\"utf-8\">\n");
		page.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n");
		page.append("    <meta name=\"description\" content=\"\">\n");
		page.append("    <meta name=\"author\" content=\"\">\n");
		page.append("    <title>Confirm Log Out?</title>\n");
		page.append("    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" "
				+ "rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n");
		page.append("    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" "
				+ "rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n");
		page.append("  </head>\n");
		page.append("  <body>\n");
		page.append("     <div class=\"container\">\n");
		page.append("      <form class=\"form-signin\" method=\"post\" action=\"" + contextPath + "/logout\">\n");
		page.append("        <h2 class=\"form-signin-heading\">Are you sure you want to log out?</h2>\n");
		page.append(csrfTokenHtmlInput);
		page.append("        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Log Out</button>\n");
		page.append("      </form>\n");
		page.append("    </div>\n");
		page.append("  </body>\n");
		page.append("</html>");
		return page.toString().getBytes(Charset.defaultCharset());
	}

	private static String csrfToken(CsrfToken token) {
		return "          <input type=\"hidden\" name=\"" + token.getParameterName() + "\" value=\"" + token.getToken()
				+ "\">\n";
	}

}
