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

package org.springframework.security.web.server.authentication.session;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.mock.web.server.MockWebSession;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RegisterSessionServerAuthenticationSuccessHandler;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.WebSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class RegisterSessionServerAuthenticationSuccessHandlerTests {

	@InjectMocks
	RegisterSessionServerAuthenticationSuccessHandler strategy;

	@Mock
	ReactiveSessionRegistry sessionRegistry;

	@Mock
	WebFilterChain filterChain;

	WebSession session = new MockWebSession();

	ServerWebExchange serverWebExchange = MockServerWebExchange.builder(MockServerHttpRequest.get(""))
		.session(this.session)
		.build();

	@Test
	void constructorWhenSessionRegistryNullThenException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new RegisterSessionServerAuthenticationSuccessHandler(null))
			.withMessage("sessionRegistry cannot be null");
	}

	@Test
	void onAuthenticationWhenSessionExistsThenSaveSessionInformation() {
		given(this.sessionRegistry.saveSessionInformation(any())).willReturn(Mono.empty());
		WebFilterExchange webFilterExchange = new WebFilterExchange(this.serverWebExchange, this.filterChain);
		Authentication authentication = TestAuthentication.authenticatedUser();
		this.strategy.onAuthenticationSuccess(webFilterExchange, authentication).block();
		ArgumentCaptor<ReactiveSessionInformation> captor = ArgumentCaptor.forClass(ReactiveSessionInformation.class);
		verify(this.sessionRegistry).saveSessionInformation(captor.capture());
		assertThat(captor.getValue().getSessionId()).isEqualTo(this.session.getId());
		assertThat(captor.getValue().getLastAccessTime()).isEqualTo(this.session.getLastAccessTime());
		assertThat(captor.getValue().getPrincipal()).isEqualTo(authentication.getPrincipal());
	}

}
