/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import org.junit.Test;

import org.springframework.security.oauth2.jose.TestKeys;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;

public class JwtDecoderProviderConfigurationUtilsTests {

	@Test
	public void getSignatureAlgorithmsWhenJwkSetSpecifiesAlgorithmThenUses() throws Exception {
		JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
		RSAKey key = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY).keyUse(KeyUse.SIGNATURE)
				.algorithm(JWSAlgorithm.RS384).build();
		given(jwkSource.get(any(JWKSelector.class), isNull())).willReturn(Collections.singletonList(key));
		Set<SignatureAlgorithm> algorithms = JwtDecoderProviderConfigurationUtils.getSignatureAlgorithms(jwkSource);
		assertThat(algorithms).containsOnly(SignatureAlgorithm.RS384);
	}

	@Test
	public void getSignatureAlgorithmsWhenJwkSetIsEmptyThenIllegalArgumentException() throws Exception {
		JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
		given(jwkSource.get(any(JWKSelector.class), isNull())).willReturn(Collections.emptyList());
		assertThatIllegalArgumentException()
				.isThrownBy(() -> JwtDecoderProviderConfigurationUtils.getSignatureAlgorithms(jwkSource));
	}

	@Test
	public void getSignatureAlgorithmsWhenJwkSetSpecifiesFamilyThenUses() throws Exception {
		JWKSource<SecurityContext> jwkSource = mock(JWKSource.class);
		// Test parameters are from Anders Rundgren, public only
		ECKey ecKey = new ECKey.Builder(Curve.P_256, new Base64URL("3l2Da_flYc-AuUTm2QzxgyvJxYM_2TeB9DMlwz7j1PE"),
				new Base64URL("-kjT7Wrfhwsi9SG6H4UXiyUiVE9GHCLauslksZ3-_t0")).keyUse(KeyUse.SIGNATURE).build();
		RSAKey rsaKey = new RSAKey.Builder(TestKeys.DEFAULT_PUBLIC_KEY).keyUse(KeyUse.ENCRYPTION).build();
		given(jwkSource.get(any(JWKSelector.class), isNull())).willReturn(Arrays.asList(ecKey, rsaKey));
		Set<SignatureAlgorithm> algorithms = JwtDecoderProviderConfigurationUtils.getSignatureAlgorithms(jwkSource);
		assertThat(algorithms).contains(SignatureAlgorithm.ES256, SignatureAlgorithm.ES384, SignatureAlgorithm.ES512);
	}

}
