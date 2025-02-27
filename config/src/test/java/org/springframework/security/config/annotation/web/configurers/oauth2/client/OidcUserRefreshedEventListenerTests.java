/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.authentication.event.OidcUserRefreshedEvent;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.TestOidcUsers;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link OidcUserRefreshedEventListener}.
 *
 * @author Steve Riesenberg
 */
public class OidcUserRefreshedEventListenerTests {

	private OidcUserRefreshedEventListener eventListener;

	private SecurityContextRepository securityContextRepository;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	@BeforeEach
	public void setUp() {
		this.securityContextRepository = mock(SecurityContextRepository.class);
		this.eventListener = new OidcUserRefreshedEventListener();
		this.eventListener.setSecurityContextRepository(this.securityContextRepository);

		this.request = new MockHttpServletRequest("GET", "");
		this.request.setServletPath("/");
		this.response = new MockHttpServletResponse();
	}

	@AfterEach
	public void cleanUp() {
		SecurityContextHolder.clearContext();
		RequestContextHolder.resetRequestAttributes();
	}

	@Test
	public void setSecurityContextHolderStrategyWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.eventListener.setSecurityContextHolderStrategy(null))
			.withMessage("securityContextHolderStrategy cannot be null");
	}

	@Test
	public void setSecurityContextRepositoryWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.eventListener.setSecurityContextRepository(null))
			.withMessage("securityContextRepository cannot be null");
	}

	@Test
	public void onApplicationEventWhenRequestAttributesSetThenSecurityContextSaved() {
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(this.request, this.response));

		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.oidcAccessTokenResponse()
			.build();
		OidcUser oldOidcUser = TestOidcUsers.create();
		OidcUser newOidcUser = TestOidcUsers.create();
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(newOidcUser,
				newOidcUser.getAuthorities(), "test");
		OidcUserRefreshedEvent event = new OidcUserRefreshedEvent(accessTokenResponse, oldOidcUser, newOidcUser,
				authentication);
		this.eventListener.onApplicationEvent(event);

		ArgumentCaptor<SecurityContext> securityContextCaptor = ArgumentCaptor.forClass(SecurityContext.class);
		verify(this.securityContextRepository).saveContext(securityContextCaptor.capture(), eq(this.request),
				eq(this.response));
		verifyNoMoreInteractions(this.securityContextRepository);

		SecurityContext securityContext = securityContextCaptor.getValue();
		assertThat(securityContext).isNotNull();
		assertThat(securityContext).isSameAs(SecurityContextHolder.getContext());
		assertThat(securityContext.getAuthentication()).isSameAs(authentication);
	}

	@Test
	public void onApplicationEventWhenRequestAttributesNotSetThenSecurityContextNotSaved() {
		OAuth2AccessTokenResponse accessTokenResponse = TestOAuth2AccessTokenResponses.oidcAccessTokenResponse()
			.build();
		OidcUser oldOidcUser = TestOidcUsers.create();
		OidcUser newOidcUser = TestOidcUsers.create();
		OAuth2AuthenticationToken authentication = new OAuth2AuthenticationToken(newOidcUser,
				newOidcUser.getAuthorities(), "test");
		OidcUserRefreshedEvent event = new OidcUserRefreshedEvent(accessTokenResponse, oldOidcUser, newOidcUser,
				authentication);
		OidcUserRefreshedEventListener eventListener = new OidcUserRefreshedEventListener();
		eventListener.setSecurityContextRepository(this.securityContextRepository);
		eventListener.onApplicationEvent(event);
		verifyNoInteractions(this.securityContextRepository);

		SecurityContext securityContext = SecurityContextHolder.getContext();
		assertThat(securityContext).isNotNull();
		assertThat(securityContext.getAuthentication()).isSameAs(authentication);
	}

}
