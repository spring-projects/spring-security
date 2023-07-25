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

package org.springframework.security.web.session;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.session.WebSessionStore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link WebSessionStoreReactiveSessionRegistry}
 *
 * @author Marcus da Coregio
 */
class WebSessionStoreReactiveSessionRegistryTests {

	WebSessionStore webSessionStore = mock();

	WebSessionStoreReactiveSessionRegistry registry = new WebSessionStoreReactiveSessionRegistry(this.webSessionStore);

	@Test
	void constructorWhenWebSessionStoreNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new WebSessionStoreReactiveSessionRegistry(null))
			.withMessage("webSessionStore cannot be null");
	}

	@Test
	void getSessionInformationWhenSavedThenReturnsWebSessionInformation() {
		ReactiveSessionInformation session = createSession();
		this.registry.saveSessionInformation(session).block();
		ReactiveSessionInformation saved = this.registry.getSessionInformation(session.getSessionId()).block();
		assertThat(saved).isInstanceOf(WebSessionStoreReactiveSessionRegistry.WebSessionInformation.class);
		assertThat(saved.getPrincipal()).isEqualTo(session.getPrincipal());
		assertThat(saved.getSessionId()).isEqualTo(session.getSessionId());
		assertThat(saved.getLastAccessTime()).isEqualTo(session.getLastAccessTime());
	}

	@Test
	void invalidateWhenReturnedFromGetSessionInformationThenWebSessionInvalidatedAndRemovedFromRegistry() {
		ReactiveSessionInformation session = createSession();
		WebSession webSession = mock();
		given(webSession.invalidate()).willReturn(Mono.empty());
		given(this.webSessionStore.retrieveSession(session.getSessionId())).willReturn(Mono.just(webSession));

		this.registry.saveSessionInformation(session).block();
		ReactiveSessionInformation saved = this.registry.getSessionInformation(session.getSessionId()).block();
		saved.invalidate().block();
		verify(webSession).invalidate();
		assertThat(this.registry.getSessionInformation(saved.getSessionId()).block()).isNull();
	}

	@Test
	void invalidateWhenReturnedFromRemoveSessionInformationThenWebSessionInvalidatedAndRemovedFromRegistry() {
		ReactiveSessionInformation session = createSession();
		WebSession webSession = mock();
		given(webSession.invalidate()).willReturn(Mono.empty());
		given(this.webSessionStore.retrieveSession(session.getSessionId())).willReturn(Mono.just(webSession));

		this.registry.saveSessionInformation(session).block();
		ReactiveSessionInformation saved = this.registry.removeSessionInformation(session.getSessionId()).block();
		saved.invalidate().block();
		verify(webSession).invalidate();
		assertThat(this.registry.getSessionInformation(saved.getSessionId()).block()).isNull();
	}

	@Test
	void invalidateWhenReturnedFromGetAllSessionsThenWebSessionInvalidatedAndRemovedFromRegistry() {
		ReactiveSessionInformation session = createSession();
		WebSession webSession = mock();
		given(webSession.invalidate()).willReturn(Mono.empty());
		given(this.webSessionStore.retrieveSession(session.getSessionId())).willReturn(Mono.just(webSession));

		this.registry.saveSessionInformation(session).block();
		List<ReactiveSessionInformation> saved = this.registry.getAllSessions(session.getPrincipal(), false)
			.collectList()
			.block();
		saved.forEach((info) -> info.invalidate().block());
		verify(webSession).invalidate();
		assertThat(this.registry.getAllSessions(session.getPrincipal(), false).collectList().block()).isEmpty();
	}

	@Test
	void setSessionRegistryThenUses() {
		ReactiveSessionRegistry sessionRegistry = mock();
		given(sessionRegistry.saveSessionInformation(any())).willReturn(Mono.empty());
		given(sessionRegistry.removeSessionInformation(any())).willReturn(Mono.empty());
		given(sessionRegistry.updateLastAccessTime(any())).willReturn(Mono.empty());
		given(sessionRegistry.getSessionInformation(any())).willReturn(Mono.empty());
		given(sessionRegistry.getAllSessions(any(), anyBoolean())).willReturn(Flux.empty());
		this.registry.setSessionRegistry(sessionRegistry);
		ReactiveSessionInformation session = createSession();
		this.registry.saveSessionInformation(session).block();
		verify(sessionRegistry).saveSessionInformation(any());
		this.registry.removeSessionInformation(session.getSessionId()).block();
		verify(sessionRegistry).removeSessionInformation(any());
		this.registry.updateLastAccessTime(session.getSessionId()).block();
		verify(sessionRegistry).updateLastAccessTime(any());
		this.registry.getSessionInformation(session.getSessionId()).block();
		verify(sessionRegistry).getSessionInformation(any());
		this.registry.getAllSessions(session.getPrincipal(), false).blockFirst();
		verify(sessionRegistry).getAllSessions(any(), eq(false));
	}

	private static ReactiveSessionInformation createSession() {
		return new ReactiveSessionInformation("principal", "sessionId", Instant.now());
	}

}
