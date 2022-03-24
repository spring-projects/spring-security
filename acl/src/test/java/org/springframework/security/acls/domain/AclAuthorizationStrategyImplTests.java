/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.acls.domain;

import java.util.Arrays;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.acls.model.Acl;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 *
 */
@ExtendWith(MockitoExtension.class)
public class AclAuthorizationStrategyImplTests {

	SecurityContext context;

	@Mock
	Acl acl;

	@Mock
	SecurityContextHolderStrategy securityContextHolderStrategy;

	GrantedAuthority authority;

	AclAuthorizationStrategyImpl strategy;

	@BeforeEach
	public void setup() {
		this.authority = new SimpleGrantedAuthority("ROLE_AUTH");
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("foo", "bar",
				Arrays.asList(this.authority));
		authentication.setAuthenticated(true);
		this.context = new SecurityContextImpl(authentication);
		SecurityContextHolder.setContext(this.context);
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	// gh-4085
	@Test
	public void securityCheckWhenCustomAuthorityThenNameIsUsed() {
		this.strategy = new AclAuthorizationStrategyImpl(new CustomAuthority());
		this.strategy.securityCheck(this.acl, AclAuthorizationStrategy.CHANGE_GENERAL);
	}

	// gh-9425
	@Test
	public void securityCheckWhenAclOwnedByGrantedAuthority() {
		given(this.acl.getOwner()).willReturn(new GrantedAuthoritySid("ROLE_AUTH"));
		this.strategy = new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_SYSTEM_ADMIN"));
		this.strategy.securityCheck(this.acl, AclAuthorizationStrategy.CHANGE_GENERAL);
	}

	@Test
	public void securityCheckWhenCustomSecurityContextHolderStrategyThenUses() {
		given(this.securityContextHolderStrategy.getContext()).willReturn(this.context);
		given(this.acl.getOwner()).willReturn(new GrantedAuthoritySid("ROLE_AUTH"));
		this.strategy = new AclAuthorizationStrategyImpl(new SimpleGrantedAuthority("ROLE_SYSTEM_ADMIN"));
		this.strategy.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		this.strategy.securityCheck(this.acl, AclAuthorizationStrategy.CHANGE_GENERAL);
		verify(this.securityContextHolderStrategy).getContext();
	}

	@SuppressWarnings("serial")
	class CustomAuthority implements GrantedAuthority {

		@Override
		public String getAuthority() {
			return AclAuthorizationStrategyImplTests.this.authority.getAuthority();
		}

	}

}
