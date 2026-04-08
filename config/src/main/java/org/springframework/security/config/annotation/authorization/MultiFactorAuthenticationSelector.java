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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/**
 * Uses {@link EnableMultiFactorAuthentication} to configure a
 * {@link DefaultAuthorizationManagerFactory}.
 * <p>
 * When {@link EnableMultiFactorAuthentication#when()} includes
 * {@link MultiFactorCondition#WEBAUTHN_REGISTERED}, validates that
 * {@link EnableMultiFactorAuthentication#authorities()} includes
 * {@link org.springframework.security.core.authority.FactorGrantedAuthority#WEBAUTHN_AUTHORITY}
 * and throws an {@link IllegalArgumentException} if not.
 *
 * @author Rob Winch
 * @since 7.0
 * @see EnableMultiFactorAuthentication
 */
class MultiFactorAuthenticationSelector implements ImportSelector {

	@Override
	public String[] selectImports(AnnotationMetadata metadata) {
		Map<String, Object> multiFactorAuthenticationAttrs = metadata
			.getAnnotationAttributes(EnableMultiFactorAuthentication.class.getName());
		String[] authorities = (String[]) multiFactorAuthenticationAttrs.getOrDefault("authorities", new String[0]);
		MultiFactorCondition[] when = (MultiFactorCondition[]) multiFactorAuthenticationAttrs.getOrDefault("when",
				new MultiFactorCondition[0]);
		boolean hasWebAuthn = Arrays.asList(when).contains(MultiFactorCondition.WEBAUTHN_REGISTERED);
		if (hasWebAuthn && !Arrays.asList(authorities).contains(FactorGrantedAuthority.WEBAUTHN_AUTHORITY)) {
			throw new IllegalArgumentException("When when() includes " + MultiFactorCondition.WEBAUTHN_REGISTERED
					+ ", authorities() must include " + FactorGrantedAuthority.WEBAUTHN_AUTHORITY);
		}
		List<String> imports = new ArrayList<>(3);
		if (authorities.length > 0) {
			imports.add(AuthorizationManagerFactoryConfiguration.class.getName());
			if (hasWebAuthn) {
				imports.add(WhenWebAuthnRegisteredMfaConfiguration.class.getName());
			}
		}
		imports.add(EnableMfaFiltersConfiguration.class.getName());
		return imports.toArray(new String[imports.size()]);
	}

}
