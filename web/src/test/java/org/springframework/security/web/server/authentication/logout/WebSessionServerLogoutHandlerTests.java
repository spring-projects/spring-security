/*
 * Copyright 2002-2021 the original author or authors.
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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class WebSessionServerLogoutHandlerTests {

	@Mock
	ServerWebExchange webExchange;

	@Mock
	WebFilterExchange filterExchange;

	@Mock
	WebSession webSession;

	@Test
	public void shouldInvalidateWebSession() {
		doReturn(this.webExchange).when(this.filterExchange).getExchange();
		doReturn(Mono.just(this.webSession)).when(this.webExchange).getSession();
		doReturn(Mono.empty()).when(this.webSession).invalidate();

		WebSessionServerLogoutHandler handler = new WebSessionServerLogoutHandler();
		handler.logout(this.filterExchange, mock(Authentication.class)).block();

		verify(this.webSession).invalidate();
	}

}
