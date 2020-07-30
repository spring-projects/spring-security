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

package org.springframework.security.test.web.reactive.server;

import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.TestOAuth2AuthenticatedPrincipals;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames;
import org.springframework.security.web.reactive.result.method.annotation.CurrentSecurityContextArgumentResolver;
import org.springframework.security.web.server.context.SecurityContextServerWebExchangeWebFilter;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Josh Cummings
 * @since 5.3
 */
@RunWith(MockitoJUnitRunner.class)
public class SecurityMockServerConfigurerOpaqueTokenTests extends AbstractMockServerConfigurersTests {

	private GrantedAuthority authority1 = new SimpleGrantedAuthority("one");

	private GrantedAuthority authority2 = new SimpleGrantedAuthority("two");

	private WebTestClient client = WebTestClient.bindToController(this.securityContextController)
			.webFilter(new SecurityContextServerWebExchangeWebFilter())
			.argumentResolvers((resolvers) -> resolvers
					.addCustomResolver(new CurrentSecurityContextArgumentResolver(new ReactiveAdapterRegistry())))
			.apply(SecurityMockServerConfigurers.springSecurity()).configureClient()
			.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE).build();

	@Test
	public void mockOpaqueTokenWhenUsingDefaultsThenBearerTokenAuthentication() {
		this.client.mutateWith(SecurityMockServerConfigurers.mockOpaqueToken()).get().exchange().expectStatus().isOk();

		SecurityContext context = this.securityContextController.removeSecurityContext();
		assertThat(context.getAuthentication()).isInstanceOf(BearerTokenAuthentication.class);
		BearerTokenAuthentication token = (BearerTokenAuthentication) context.getAuthentication();
		assertThat(token.getAuthorities()).isNotEmpty();
		assertThat(token.getToken()).isNotNull();
		assertThat(token.getTokenAttributes().get(OAuth2IntrospectionClaimNames.SUBJECT)).isEqualTo("user");
	}

	@Test
	public void mockOpaqueTokenWhenAuthoritiesThenBearerTokenAuthentication() {
		this.client
				.mutateWith(
						SecurityMockServerConfigurers.mockOpaqueToken().authorities(this.authority1, this.authority2))
				.get().exchange().expectStatus().isOk();

		SecurityContext context = this.securityContextController.removeSecurityContext();
		assertThat((List<GrantedAuthority>) context.getAuthentication().getAuthorities()).containsOnly(this.authority1,
				this.authority2);
	}

	@Test
	public void mockOpaqueTokenWhenAttributesThenBearerTokenAuthentication() {
		String sub = new String("my-subject");
		this.client
				.mutateWith(SecurityMockServerConfigurers.mockOpaqueToken()
						.attributes((attributes) -> attributes.put(OAuth2IntrospectionClaimNames.SUBJECT, sub)))
				.get().exchange().expectStatus().isOk();

		SecurityContext context = this.securityContextController.removeSecurityContext();
		assertThat(context.getAuthentication()).isInstanceOf(BearerTokenAuthentication.class);
		BearerTokenAuthentication token = (BearerTokenAuthentication) context.getAuthentication();
		assertThat(token.getTokenAttributes().get(OAuth2IntrospectionClaimNames.SUBJECT)).isSameAs(sub);
	}

	@Test
	public void mockOpaqueTokenWhenPrincipalThenBearerTokenAuthentication() {
		OAuth2AuthenticatedPrincipal principal = TestOAuth2AuthenticatedPrincipals.active();
		this.client.mutateWith(SecurityMockServerConfigurers.mockOpaqueToken().principal(principal)).get().exchange()
				.expectStatus().isOk();

		SecurityContext context = this.securityContextController.removeSecurityContext();
		assertThat(context.getAuthentication()).isInstanceOf(BearerTokenAuthentication.class);
		BearerTokenAuthentication token = (BearerTokenAuthentication) context.getAuthentication();
		assertThat(token.getPrincipal()).isSameAs(principal);
	}

	@Test
	public void mockOpaqueTokenWhenPrincipalSpecifiedThenLastCalledTakesPrecedence() {
		OAuth2AuthenticatedPrincipal principal = TestOAuth2AuthenticatedPrincipals
				.active((a) -> a.put("scope", "user"));

		this.client
				.mutateWith(SecurityMockServerConfigurers.mockOpaqueToken()
						.attributes((a) -> a.put(OAuth2IntrospectionClaimNames.SUBJECT, "foo")).principal(principal))
				.get().exchange().expectStatus().isOk();

		SecurityContext context = this.securityContextController.removeSecurityContext();
		assertThat(context.getAuthentication()).isInstanceOf(BearerTokenAuthentication.class);
		BearerTokenAuthentication token = (BearerTokenAuthentication) context.getAuthentication();
		assertThat((String) ((OAuth2AuthenticatedPrincipal) token.getPrincipal())
				.getAttribute(OAuth2IntrospectionClaimNames.SUBJECT))
						.isEqualTo(principal.getAttribute(OAuth2IntrospectionClaimNames.SUBJECT));

		this.client
				.mutateWith(SecurityMockServerConfigurers.mockOpaqueToken().principal(principal)
						.attributes((a) -> a.put(OAuth2IntrospectionClaimNames.SUBJECT, "bar")))
				.get().exchange().expectStatus().isOk();

		context = this.securityContextController.removeSecurityContext();
		assertThat(context.getAuthentication()).isInstanceOf(BearerTokenAuthentication.class);
		token = (BearerTokenAuthentication) context.getAuthentication();
		assertThat((String) ((OAuth2AuthenticatedPrincipal) token.getPrincipal())
				.getAttribute(OAuth2IntrospectionClaimNames.SUBJECT)).isEqualTo("bar");
	}

}
