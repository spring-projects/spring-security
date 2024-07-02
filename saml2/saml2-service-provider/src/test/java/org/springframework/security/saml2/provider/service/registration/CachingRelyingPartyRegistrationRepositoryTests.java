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

package org.springframework.security.saml2.provider.service.registration;

import java.util.concurrent.Callable;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.cache.Cache;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link CachingRelyingPartyRegistrationRepository}
 */
@ExtendWith(MockitoExtension.class)
public class CachingRelyingPartyRegistrationRepositoryTests {

	@Mock
	Callable<Iterable<RelyingPartyRegistration>> callable;

	@InjectMocks
	CachingRelyingPartyRegistrationRepository registrations;

	@Test
	public void iteratorWhenResolvableThenPopulatesCache() throws Exception {
		given(this.callable.call()).willReturn(mock(IterableRelyingPartyRegistrationRepository.class));
		this.registrations.iterator();
		verify(this.callable).call();
		this.registrations.iterator();
		verifyNoMoreInteractions(this.callable);
	}

	@Test
	public void iteratorWhenExceptionThenPropagates() throws Exception {
		given(this.callable.call()).willThrow(IllegalStateException.class);
		assertThatExceptionOfType(Cache.ValueRetrievalException.class).isThrownBy(this.registrations::iterator)
			.withCauseInstanceOf(IllegalStateException.class);
	}

	@Test
	public void findByRegistrationIdWhenResolvableThenPopulatesCache() throws Exception {
		given(this.callable.call()).willReturn(mock(IterableRelyingPartyRegistrationRepository.class));
		this.registrations.findByRegistrationId("id");
		verify(this.callable).call();
		this.registrations.findByRegistrationId("id");
		verifyNoMoreInteractions(this.callable);
	}

	@Test
	public void findUniqueByAssertingPartyEntityIdWhenResolvableThenPopulatesCache() throws Exception {
		given(this.callable.call()).willReturn(mock(IterableRelyingPartyRegistrationRepository.class));
		this.registrations.findUniqueByAssertingPartyEntityId("id");
		verify(this.callable).call();
		this.registrations.findUniqueByAssertingPartyEntityId("id");
		verifyNoMoreInteractions(this.callable);
	}

}
