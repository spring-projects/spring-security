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

package org.springframework.security.web.server.authentication.logout;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.test.publisher.PublisherProbe;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * @author Max Batischev
 * @since 6.3
 */
@ExtendWith(MockitoExtension.class)
public class DelegatingServerLogoutSuccessHandlerTests {

	@Mock
	private ServerLogoutSuccessHandler delegate1;

	@Mock
	private ServerLogoutSuccessHandler delegate2;

	private final PublisherProbe<Void> delegate1Result = PublisherProbe.empty();

	private final PublisherProbe<Void> delegate2Result = PublisherProbe.empty();

	@Mock
	private WebFilterExchange exchange;

	@Mock
	private Authentication authentication;

	private DelegatingServerLogoutSuccessHandler logoutSuccessHandler;

	@Test
	public void logoutWhenDelegate1AndDelegate2PresentThenExecuted() {
		given(this.delegate1.onLogoutSuccess(any(WebFilterExchange.class), any(Authentication.class)))
			.willReturn(this.delegate1Result.mono());
		given(this.delegate2.onLogoutSuccess(any(WebFilterExchange.class), any(Authentication.class)))
			.willReturn(this.delegate2Result.mono());
		this.logoutSuccessHandler = new DelegatingServerLogoutSuccessHandler(this.delegate1, this.delegate2);

		this.logoutSuccessHandler.onLogoutSuccess(this.exchange, this.authentication).block();

		this.delegate1Result.assertWasSubscribed();
		this.delegate2Result.assertWasSubscribed();
	}

	@Test
	public void logoutWhenDelegate1PresentThenExecuted() {
		given(this.delegate1.onLogoutSuccess(any(WebFilterExchange.class), any(Authentication.class)))
			.willReturn(this.delegate1Result.mono());
		this.logoutSuccessHandler = new DelegatingServerLogoutSuccessHandler(List.of(this.delegate1));

		this.logoutSuccessHandler.onLogoutSuccess(this.exchange, this.authentication).block();

		this.delegate1Result.assertWasSubscribed();
	}

}
