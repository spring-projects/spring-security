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

package org.springframework.security.oauth2.server.resource.introspection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

/**
 * Tests for {@link OAuth2IntrospectionAuthenticatedPrincipal}
 *
 * @author David Kovac
 */
public class OAuth2IntrospectionAuthenticatedPrincipalTests {

	private static final String AUTHORITY = "SCOPE_read";

	private static final Collection<GrantedAuthority> AUTHORITIES = AuthorityUtils.createAuthorityList(AUTHORITY);

	private static final String SUBJECT = "test-subject";

	private static final String ACTIVE_CLAIM = "active";

	private static final String CLIENT_ID_CLAIM = "client_id";

	private static final String USERNAME_CLAIM = "username";

	private static final String TOKEN_TYPE_CLAIM = "token_type";

	private static final String EXP_CLAIM = "exp";

	private static final String IAT_CLAIM = "iat";

	private static final String NBF_CLAIM = "nbf";

	private static final String SUB_CLAIM = "sub";

	private static final String AUD_CLAIM = "aud";

	private static final String ISS_CLAIM = "iss";

	private static final String JTI_CLAIM = "jti";

	private static final boolean ACTIVE_VALUE = true;

	private static final String CLIENT_ID_VALUE = "client-id-1";

	private static final String USERNAME_VALUE = "username-1";

	private static final String TOKEN_TYPE_VALUE = "token-type-1";

	private static final long EXP_VALUE = Instant.now().plusSeconds(60).getEpochSecond();

	private static final long IAT_VALUE = Instant.now().getEpochSecond();

	private static final long NBF_VALUE = Instant.now().plusSeconds(5).getEpochSecond();

	private static final String SUB_VALUE = "subject1";

	private static final List<String> AUD_VALUE = Arrays.asList("aud1", "aud2");

	private static final String ISS_VALUE = "https://provider.com";

	private static final String JTI_VALUE = "jwt-id-1";

	private static final Map<String, Object> CLAIMS;

	static {
		CLAIMS = new HashMap<>();
		CLAIMS.put(ACTIVE_CLAIM, ACTIVE_VALUE);
		CLAIMS.put(CLIENT_ID_CLAIM, CLIENT_ID_VALUE);
		CLAIMS.put(USERNAME_CLAIM, USERNAME_VALUE);
		CLAIMS.put(TOKEN_TYPE_CLAIM, TOKEN_TYPE_VALUE);
		CLAIMS.put(EXP_CLAIM, EXP_VALUE);
		CLAIMS.put(IAT_CLAIM, IAT_VALUE);
		CLAIMS.put(NBF_CLAIM, NBF_VALUE);
		CLAIMS.put(SUB_CLAIM, SUB_VALUE);
		CLAIMS.put(AUD_CLAIM, AUD_VALUE);
		CLAIMS.put(ISS_CLAIM, ISS_VALUE);
		CLAIMS.put(JTI_CLAIM, JTI_VALUE);
	}

	@Test
	public void constructorWhenAttributesIsNullOrEmptyThenIllegalArgumentException() {
		assertThatCode(() -> new OAuth2IntrospectionAuthenticatedPrincipal(null, AUTHORITIES))
				.isInstanceOf(IllegalArgumentException.class);

		assertThatCode(() -> new OAuth2IntrospectionAuthenticatedPrincipal(Collections.emptyMap(), AUTHORITIES))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void constructorWhenAuthoritiesIsNullOrEmptyThenNoAuthorities() {
		Collection<? extends GrantedAuthority> authorities = new OAuth2IntrospectionAuthenticatedPrincipal(CLAIMS, null)
				.getAuthorities();
		assertThat(authorities).isEmpty();

		authorities = new OAuth2IntrospectionAuthenticatedPrincipal(CLAIMS, Collections.emptyList()).getAuthorities();
		assertThat(authorities).isEmpty();
	}

	@Test
	public void constructorWhenNameIsNullThenFallsbackToSubAttribute() {
		OAuth2AuthenticatedPrincipal principal = new OAuth2IntrospectionAuthenticatedPrincipal(null, CLAIMS,
				AUTHORITIES);
		assertThat(principal.getName()).isEqualTo(CLAIMS.get(SUB_CLAIM));
	}

	@Test
	public void constructorWhenAttributesAuthoritiesProvidedThenCreated() {
		OAuth2IntrospectionAuthenticatedPrincipal principal = new OAuth2IntrospectionAuthenticatedPrincipal(CLAIMS,
				AUTHORITIES);

		assertThat(principal.getName()).isEqualTo(CLAIMS.get(SUB_CLAIM));
		assertThat(principal.getAttributes()).isEqualTo(CLAIMS);
		assertThat(principal.getClaims()).isEqualTo(CLAIMS);
		assertThat(principal.isActive()).isEqualTo(ACTIVE_VALUE);
		assertThat(principal.getClientId()).isEqualTo(CLIENT_ID_VALUE);
		assertThat(principal.getUsername()).isEqualTo(USERNAME_VALUE);
		assertThat(principal.getTokenType()).isEqualTo(TOKEN_TYPE_VALUE);
		assertThat(principal.getExpiresAt().getEpochSecond()).isEqualTo(EXP_VALUE);
		assertThat(principal.getIssuedAt().getEpochSecond()).isEqualTo(IAT_VALUE);
		assertThat(principal.getNotBefore().getEpochSecond()).isEqualTo(NBF_VALUE);
		assertThat(principal.getSubject()).isEqualTo(SUB_VALUE);
		assertThat(principal.getAudience()).isEqualTo(AUD_VALUE);
		assertThat(principal.getIssuer().toString()).isEqualTo(ISS_VALUE);
		assertThat(principal.getId()).isEqualTo(JTI_VALUE);
		assertThat(principal.getAuthorities()).hasSize(1);
		assertThat(principal.getAuthorities().iterator().next().getAuthority()).isEqualTo(AUTHORITY);
	}

	@Test
	public void constructorWhenAllParametersProvidedAndValidThenCreated() {
		OAuth2IntrospectionAuthenticatedPrincipal principal = new OAuth2IntrospectionAuthenticatedPrincipal(SUBJECT,
				CLAIMS, AUTHORITIES);

		assertThat(principal.getName()).isEqualTo(SUBJECT);
		assertThat(principal.getAttributes()).isEqualTo(CLAIMS);
		assertThat(principal.getClaims()).isEqualTo(CLAIMS);
		assertThat(principal.isActive()).isEqualTo(ACTIVE_VALUE);
		assertThat(principal.getClientId()).isEqualTo(CLIENT_ID_VALUE);
		assertThat(principal.getUsername()).isEqualTo(USERNAME_VALUE);
		assertThat(principal.getTokenType()).isEqualTo(TOKEN_TYPE_VALUE);
		assertThat(principal.getExpiresAt().getEpochSecond()).isEqualTo(EXP_VALUE);
		assertThat(principal.getIssuedAt().getEpochSecond()).isEqualTo(IAT_VALUE);
		assertThat(principal.getNotBefore().getEpochSecond()).isEqualTo(NBF_VALUE);
		assertThat(principal.getSubject()).isEqualTo(SUB_VALUE);
		assertThat(principal.getAudience()).isEqualTo(AUD_VALUE);
		assertThat(principal.getIssuer().toString()).isEqualTo(ISS_VALUE);
		assertThat(principal.getId()).isEqualTo(JTI_VALUE);
		assertThat(principal.getAuthorities()).hasSize(1);
		assertThat(principal.getAuthorities().iterator().next().getAuthority()).isEqualTo(AUTHORITY);
	}

	@Test
	public void getNameWhenInConstructorThenReturns() {
		OAuth2AuthenticatedPrincipal principal = new OAuth2IntrospectionAuthenticatedPrincipal(SUB_VALUE, CLAIMS,
				AUTHORITIES);
		assertThat(principal.getName()).isEqualTo(SUB_VALUE);
	}

	@Test
	public void getAttributeWhenGivenKeyThenReturnsValue() {
		OAuth2AuthenticatedPrincipal principal = new OAuth2IntrospectionAuthenticatedPrincipal(CLAIMS, AUTHORITIES);

		assertThat((Object) principal.getAttribute(ACTIVE_CLAIM)).isEqualTo(ACTIVE_VALUE);
		assertThat((Object) principal.getAttribute(CLIENT_ID_CLAIM)).isEqualTo(CLIENT_ID_VALUE);
		assertThat((Object) principal.getAttribute(USERNAME_CLAIM)).isEqualTo(USERNAME_VALUE);
		assertThat((Object) principal.getAttribute(TOKEN_TYPE_CLAIM)).isEqualTo(TOKEN_TYPE_VALUE);
		assertThat((Object) principal.getAttribute(EXP_CLAIM)).isEqualTo(EXP_VALUE);
		assertThat((Object) principal.getAttribute(IAT_CLAIM)).isEqualTo(IAT_VALUE);
		assertThat((Object) principal.getAttribute(NBF_CLAIM)).isEqualTo(NBF_VALUE);
		assertThat((Object) principal.getAttribute(SUB_CLAIM)).isEqualTo(SUB_VALUE);
		assertThat((Object) principal.getAttribute(AUD_CLAIM)).isEqualTo(AUD_VALUE);
		assertThat((Object) principal.getAttribute(ISS_CLAIM)).isEqualTo(ISS_VALUE);
		assertThat((Object) principal.getAttribute(JTI_CLAIM)).isEqualTo(JTI_VALUE);
	}

}
