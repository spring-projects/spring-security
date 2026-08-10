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

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link MultiFactorAuthenticationSelector}.
 *
 * @author Rob Winch
 */
class MultiFactorAuthenticationSelectorTests {

	private final MultiFactorAuthenticationSelector selector = new MultiFactorAuthenticationSelector();

	@Test
	void selectImportsWhenWhenIsEmptyAndAuthoritiesSpecifiedThenReturnsImportsWithoutWebAuthnConfig() {
		AnnotationMetadata metadata = metadata(new MultiFactorCondition[0], FactorGrantedAuthority.OTT_AUTHORITY,
				FactorGrantedAuthority.PASSWORD_AUTHORITY);
		String[] imports = this.selector.selectImports(metadata);
		assertThat(imports).isNotEmpty();
		assertThat(imports).doesNotContain(WhenWebAuthnRegisteredMfaConfiguration.class.getName());
	}

	@Test
	void selectImportsWhenWhenOmittedThenDefaultsToEmptyAndReturnsImports() {
		AnnotationMetadata metadata = metadataWithoutWhen(FactorGrantedAuthority.OTT_AUTHORITY,
				FactorGrantedAuthority.PASSWORD_AUTHORITY);
		String[] imports = this.selector.selectImports(metadata);
		assertThat(imports).isNotEmpty();
		assertThat(imports).doesNotContain(WhenWebAuthnRegisteredMfaConfiguration.class.getName());
	}

	@Test
	void selectImportsWhenHasWebAuthnConditionAndAuthoritiesIncludesWebAuthnThenReturnsImports() {
		AnnotationMetadata metadata = metadata(new MultiFactorCondition[] { MultiFactorCondition.WEBAUTHN_REGISTERED },
				FactorGrantedAuthority.OTT_AUTHORITY, FactorGrantedAuthority.PASSWORD_AUTHORITY,
				FactorGrantedAuthority.WEBAUTHN_AUTHORITY);
		String[] imports = this.selector.selectImports(metadata);
		assertThat(imports).isNotEmpty();
	}

	@Test
	void selectImportsWhenHasWebAuthnConditionAndAuthoritiesOnlyWebAuthnThenReturnsImports() {
		AnnotationMetadata metadata = metadata(new MultiFactorCondition[] { MultiFactorCondition.WEBAUTHN_REGISTERED },
				FactorGrantedAuthority.WEBAUTHN_AUTHORITY);
		String[] imports = this.selector.selectImports(metadata);
		assertThat(imports).isNotEmpty();
	}

	@Test
	void selectImportsWhenHasWebAuthnConditionAndAuthoritiesEmptyThenThrowsException() {
		AnnotationMetadata metadata = metadata(new MultiFactorCondition[] { MultiFactorCondition.WEBAUTHN_REGISTERED });
		assertThatIllegalArgumentException().isThrownBy(() -> this.selector.selectImports(metadata))
			.withMessageContaining("authorities() must include " + FactorGrantedAuthority.WEBAUTHN_AUTHORITY);
	}

	@Test
	void selectImportsWhenHasWebAuthnConditionAndAuthoritiesExcludesWebAuthnThenThrowsException() {
		AnnotationMetadata metadata = metadata(new MultiFactorCondition[] { MultiFactorCondition.WEBAUTHN_REGISTERED },
				FactorGrantedAuthority.OTT_AUTHORITY, FactorGrantedAuthority.PASSWORD_AUTHORITY);
		assertThatIllegalArgumentException().isThrownBy(() -> this.selector.selectImports(metadata))
			.withMessageContaining("authorities() must include " + FactorGrantedAuthority.WEBAUTHN_AUTHORITY);
	}

	private static AnnotationMetadata metadata(MultiFactorCondition[] when, String... authorities) {
		AnnotationMetadata metadata = mock(AnnotationMetadata.class);
		Map<String, Object> attrs = new HashMap<>();
		attrs.put("authorities", authorities);
		attrs.put("when", when);
		given(metadata.getAnnotationAttributes(EnableMultiFactorAuthentication.class.getName())).willReturn(attrs);
		return metadata;
	}

	private static AnnotationMetadata metadataWithoutWhen(String... authorities) {
		AnnotationMetadata metadata = mock(AnnotationMetadata.class);
		Map<String, Object> attrs = new HashMap<>();
		attrs.put("authorities", authorities);
		given(metadata.getAnnotationAttributes(EnableMultiFactorAuthentication.class.getName())).willReturn(attrs);
		return metadata;
	}

}
