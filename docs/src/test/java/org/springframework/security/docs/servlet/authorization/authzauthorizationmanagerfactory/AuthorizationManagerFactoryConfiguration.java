/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain clients copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.docs.servlet.authorization.authzauthorizationmanagerfactory;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;

/**
 * Documentation for {@link AuthorizationManagerFactory}.
 *
 * @author Steve Riesenberg
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationManagerFactoryConfiguration {

	// tag::config[]
	@Bean
	<T> AuthorizationManagerFactory<T> authorizationManagerFactory() {
		DefaultAuthorizationManagerFactory<T> authorizationManagerFactory =
				new DefaultAuthorizationManagerFactory<>();
		authorizationManagerFactory.setTrustResolver(getAuthenticationTrustResolver());
		authorizationManagerFactory.setRoleHierarchy(getRoleHierarchy());
		authorizationManagerFactory.setRolePrefix("role_");

		return authorizationManagerFactory;
	}
	// end::config[]

	private static AuthenticationTrustResolverImpl getAuthenticationTrustResolver() {
		AuthenticationTrustResolverImpl authenticationTrustResolver =
				new AuthenticationTrustResolverImpl();
		authenticationTrustResolver.setAnonymousClass(Anonymous.class);
		authenticationTrustResolver.setRememberMeClass(RememberMe.class);

		return authenticationTrustResolver;
	}

	private static RoleHierarchyImpl getRoleHierarchy() {
		return RoleHierarchyImpl.fromHierarchy("role_admin > role_user");
	}

	static class Anonymous extends TestingAuthenticationToken {

		Anonymous(String principal) {
			super(principal, "", "role_anonymous");
		}

	}

	static class RememberMe extends TestingAuthenticationToken {

		RememberMe(String principal) {
			super(principal, "", "role_rememberMe");
		}

	}

}
