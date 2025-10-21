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

package org.springframework.security.data.repository.query;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.DenyAllPermissionEvaluator;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class SecurityEvaluationContextExtensionTests {

	SecurityEvaluationContextExtension securityExtension;

	@BeforeEach
	public void setup() {
		this.securityExtension = new SecurityEvaluationContextExtension();
	}

	@AfterEach
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void getRootObjectSecurityContextHolderAuthenticationNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> getRoot().getAuthentication());
	}

	@Test
	public void getRootObjectSecurityContextHolderAuthentication() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		assertThat(getRoot().getAuthentication()).isSameAs(authentication);
	}

	@Test
	public void getRootObjectUseSecurityContextHolderStrategy() {
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getContext()).willReturn(new SecurityContextImpl(authentication));
		this.securityExtension.setSecurityContextHolderStrategy(strategy);
		assertThat(getRoot().getAuthentication()).isSameAs(authentication);
		verify(strategy).getContext();
	}

	@Test
	public void getRootObjectExplicitAuthenticationOverridesSecurityContextHolder() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "ROLE_EXPLICIT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		assertThat(getRoot().getAuthentication()).isSameAs(explicit);
	}

	@Test
	public void getRootObjectExplicitAuthentication() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "ROLE_EXPLICIT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);
		assertThat(getRoot().getAuthentication()).isSameAs(explicit);
	}

	@Test
	public void setTrustResolverWhenNullThenIllegalArgumentException() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "ROLE_EXPLICIT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);
		assertThatIllegalArgumentException().isThrownBy(() -> this.securityExtension.setTrustResolver(null))
			.withMessage("trustResolver cannot be null");
	}

	@Test
	public void setTrustResolverWhenNotNullThenVerifyRootObject() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "ROLE_EXPLICIT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);
		AuthenticationTrustResolver trustResolver = mock(AuthenticationTrustResolver.class);
		given(trustResolver.isAuthenticated(explicit)).willReturn(true);
		this.securityExtension.setTrustResolver(trustResolver);
		assertThat(getRoot().isAuthenticated()).isTrue();
		verify(trustResolver).isAuthenticated(explicit);
	}

	@Test
	public void setRoleHierarchyWhenNullThenIllegalArgumentException() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "ROLE_EXPLICIT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);
		assertThatIllegalArgumentException().isThrownBy(() -> this.securityExtension.setRoleHierarchy(null))
			.withMessage("roleHierarchy cannot be null");
	}

	@Test
	public void setRoleHierarchyWhenNotNullThenVerifyRootObject() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "ROLE_PARENT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);
		RoleHierarchy roleHierarchy = RoleHierarchyImpl.fromHierarchy("ROLE_PARENT > ROLE_EXPLICIT");
		this.securityExtension.setRoleHierarchy(roleHierarchy);
		assertThat(getRoot().hasRole("EXPLICIT")).isTrue();
	}

	@Test
	public void setPermissionEvaluatorWhenNullThenIllegalArgumentException() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "ROLE_EXPLICIT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);
		assertThatIllegalArgumentException().isThrownBy(() -> this.securityExtension.setPermissionEvaluator(null))
			.withMessage("permissionEvaluator cannot be null");
	}

	@Test
	public void setPermissionEvaluatorWhenNotNullThenVerifyRootObject() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "ROLE_EXPLICIT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);
		PermissionEvaluator permissionEvaluator = new DenyAllPermissionEvaluator();
		this.securityExtension.setPermissionEvaluator(permissionEvaluator);
		assertThat(getRoot()).extracting("permissionEvaluator").isEqualTo(permissionEvaluator);
	}

	@Test
	public void setDefaultRolePrefixWhenCustomThenVerifyRootObject() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "CUSTOM_EXPLICIT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);
		String defaultRolePrefix = "CUSTOM_";
		this.securityExtension.setDefaultRolePrefix(defaultRolePrefix);
		assertThat(getRoot().hasRole("EXPLICIT")).isTrue();
	}

	@Test
	public void getRootObjectWhenAdditionalFieldsNotSetThenVerifyDefaults() {
		TestingAuthenticationToken explicit = new TestingAuthenticationToken("explicit", "password", "ROLE_EXPLICIT");
		this.securityExtension = new SecurityEvaluationContextExtension(explicit);
		SecurityExpressionRoot<?> securityExpressionRoot = getRoot();
		assertThat(securityExpressionRoot.isAuthenticated()).isTrue();
		assertThat(securityExpressionRoot.hasRole("PARENT")).isFalse();
		assertThat(securityExpressionRoot.hasRole("EXPLICIT")).isTrue();
		assertThat(securityExpressionRoot.hasPermission(new Object(), "read")).isFalse();
	}

	private SecurityExpressionRoot<?> getRoot() {
		return this.securityExtension.getRootObject();
	}

}
