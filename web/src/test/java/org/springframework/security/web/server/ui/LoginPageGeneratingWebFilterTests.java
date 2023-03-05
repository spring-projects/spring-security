/*
 * Copyright 2002-2023 the original author or authors.
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

import java.util.Locale;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import reactor.core.publisher.Mono;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.web.WebAttributes;
import org.springframework.web.server.WebSession;

import static org.assertj.core.api.Assertions.assertThat;

public class LoginPageGeneratingWebFilterTests {

	@Test
	public void filterWhenLoginWithContextPathThenActionContainsContextPath() throws Exception {
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setFormLoginEnabled(true);
		MockServerWebExchange exchange = MockServerWebExchange
				.from(MockServerHttpRequest.get("/test/login").contextPath("/test"));
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getBodyAsString().block()).contains("action=\"/test/login\"");
	}

	@Test
	public void filterWhenLoginWithNoContextPathThenActionDoesNotContainsContextPath() throws Exception {
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setFormLoginEnabled(true);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/login"));
		filter.filter(exchange, (e) -> Mono.empty()).block();
		assertThat(exchange.getResponse().getBodyAsString().block()).contains("action=\"/login\"");
	}

	@ParameterizedTest
	@ValueSource(strings = { "ca", "cs_CZ", "de", "en", "es_ES", "fr", "it", "ja", "ko_KR", "It", "mn_MN", "pl",
			"pt_BR", "pt_PT", "ru", "uk_UA", "zh_CN", "zh_TW" })
	public void filterWhenLoginFailedThenContainsLocalizedErrorMessage(String locale) {
		LoginPageGeneratingWebFilter filter = new LoginPageGeneratingWebFilter();
		filter.setFormLoginEnabled(true);
		MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/login?error"));
		MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
		String message = messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials",
				new Locale(locale));
		AuthenticationException exception = new BadCredentialsException(message);
		WebSession session = exchange.getSession().block();
		session.getAttributes().put(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
		filter.filter(exchange, (e) -> Mono.empty()).block();
		String htmlBody = exchange.getResponse().getBodyAsString().block();
		assertThat(htmlBody).isNotNull();
		assertThat(htmlBody).contains(message);
	}

}
