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

/**
 * An interface that simplifies APIs which require the
 * {@link RelyingPartyRegistrationRepository} to also be {@link Iterable}
 *
 * @author Josh Cummings
 * @since 6.4
 * @see InMemoryRelyingPartyRegistrationRepository
 * @see CachingRelyingPartyRegistrationRepository
 */
public interface IterableRelyingPartyRegistrationRepository
		extends RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {

}
