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

package org.springframework.security.web.server.authentication.session;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.InMemoryReactiveSessionRegistry;
import org.springframework.security.core.session.ReactiveSessionInformation;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link InMemoryReactiveSessionRegistry}.
 */
class InMemoryReactiveSessionRegistryTests {

	InMemoryReactiveSessionRegistry sessionRegistry = new InMemoryReactiveSessionRegistry();

	Instant now = LocalDate.of(2023, 11, 21).atStartOfDay().toInstant(ZoneOffset.UTC);

	@Test
	void saveWhenPrincipalThenRegisterPrincipalSession() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		ReactiveSessionInformation sessionInformation = new ReactiveSessionInformation(authentication.getPrincipal(),
				"1234", this.now);
		this.sessionRegistry.saveSessionInformation(sessionInformation).block();
		List<ReactiveSessionInformation> principalSessions = this.sessionRegistry
			.getAllSessions(authentication.getPrincipal())
			.collectList()
			.block();
		assertThat(principalSessions).hasSize(1);
		assertThat(this.sessionRegistry.getSessionInformation("1234").block()).isNotNull();
	}

	@Test
	void getAllSessionsWhenMultipleSessionsThenReturnAll() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		ReactiveSessionInformation sessionInformation1 = new ReactiveSessionInformation(authentication.getPrincipal(),
				"1234", this.now);
		ReactiveSessionInformation sessionInformation2 = new ReactiveSessionInformation(authentication.getPrincipal(),
				"4321", this.now);
		ReactiveSessionInformation sessionInformation3 = new ReactiveSessionInformation(authentication.getPrincipal(),
				"9876", this.now);
		this.sessionRegistry.saveSessionInformation(sessionInformation1).block();
		this.sessionRegistry.saveSessionInformation(sessionInformation2).block();
		this.sessionRegistry.saveSessionInformation(sessionInformation3).block();
		List<ReactiveSessionInformation> sessions = this.sessionRegistry.getAllSessions(authentication.getPrincipal())
			.collectList()
			.block();
		assertThat(sessions).hasSize(3);
		assertThat(this.sessionRegistry.getSessionInformation("1234").block()).isNotNull();
		assertThat(this.sessionRegistry.getSessionInformation("4321").block()).isNotNull();
		assertThat(this.sessionRegistry.getSessionInformation("9876").block()).isNotNull();
	}

	@Test
	void removeSessionInformationThenSessionIsRemoved() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		ReactiveSessionInformation sessionInformation = new ReactiveSessionInformation(authentication.getPrincipal(),
				"1234", this.now);
		this.sessionRegistry.saveSessionInformation(sessionInformation).block();
		this.sessionRegistry.removeSessionInformation("1234").block();
		List<ReactiveSessionInformation> sessions = this.sessionRegistry.getAllSessions(authentication.getName())
			.collectList()
			.block();
		assertThat(this.sessionRegistry.getSessionInformation("1234").block()).isNull();
		assertThat(sessions).isEmpty();
	}

	@Test
	void updateLastAccessTimeThenUpdated() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		ReactiveSessionInformation sessionInformation = new ReactiveSessionInformation(authentication.getPrincipal(),
				"1234", this.now);
		this.sessionRegistry.saveSessionInformation(sessionInformation).block();
		ReactiveSessionInformation saved = this.sessionRegistry.getSessionInformation("1234").block();
		assertThat(saved.getLastAccessTime()).isNotNull();
		Instant lastAccessTimeBefore = saved.getLastAccessTime();
		this.sessionRegistry.updateLastAccessTime("1234").block();
		saved = this.sessionRegistry.getSessionInformation("1234").block();
		assertThat(saved.getLastAccessTime()).isNotNull();
		assertThat(saved.getLastAccessTime()).isAfter(lastAccessTimeBefore);
	}

}
