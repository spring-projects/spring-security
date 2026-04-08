/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.authorization;

import java.util.function.Predicate;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactories.AdditionalRequiredFactorsBuilder;
import org.springframework.security.config.Customizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

/**
 * Configuration that provides a
 * {@link Customizer}&lt;{@link AdditionalRequiredFactorsBuilder}&gt; for
 * {@link MultiFactorCondition#WEBAUTHN_REGISTERED}, requiring multi-factor authentication
 * only when the user has a WebAuthn credential record.
 *
 * @author Rob Winch
 * @since 7.1
 * @see EnableMultiFactorAuthentication#when()
 * @see MultiFactorCondition#WEBAUTHN_REGISTERED
 */
@Configuration(proxyBeanMethods = false)
class WhenWebAuthnRegisteredMfaConfiguration {

	@Bean
	Customizer<AdditionalRequiredFactorsBuilder<Object>> additionalRequiredFactorsCustomizer(
			PublicKeyCredentialUserEntityRepository userEntityRepository,
			UserCredentialRepository userCredentialRepository) {
		return (builder) -> builder.withWhen((current) -> {
			Predicate<Authentication> webAuthnRegisteredPredicate = new WebAuthnRegisteredPredicate(
					userEntityRepository, userCredentialRepository);
			if (current == null) {
				return webAuthnRegisteredPredicate;
			}
			return current.and(webAuthnRegisteredPredicate);
		});
	}

	private static final class WebAuthnRegisteredPredicate implements Predicate<Authentication> {

		private final PublicKeyCredentialUserEntityRepository userEntityRepository;

		private final UserCredentialRepository userCredentialRepository;

		private WebAuthnRegisteredPredicate(PublicKeyCredentialUserEntityRepository userEntityRepository,
				UserCredentialRepository userCredentialRepository) {
			this.userEntityRepository = userEntityRepository;
			this.userCredentialRepository = userCredentialRepository;
		}

		@Override
		public boolean test(Authentication authentication) {
			if (authentication == null || authentication.getName() == null) {
				return false;
			}
			PublicKeyCredentialUserEntity userEntity = this.userEntityRepository
				.findByUsername(authentication.getName());
			if (userEntity == null) {
				return false;
			}
			return !this.userCredentialRepository.findByUserId(userEntity.getId()).isEmpty();
		}

		@Override
		public String toString() {
			return "WEBAUTHN_REGISTERED";
		}

	}

}
