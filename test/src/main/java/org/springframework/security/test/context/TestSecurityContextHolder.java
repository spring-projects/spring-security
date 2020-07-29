/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.test.context;

import javax.servlet.FilterChain;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.Assert;

/**
 * The {@link TestSecurityContextHolder} is very similar to {@link SecurityContextHolder},
 * but is necessary for testing. For example, we cannot populate the desired
 * {@link SecurityContext} in {@link SecurityContextHolder} for web based testing. In a
 * web request, the {@link SecurityContextPersistenceFilter} will override the
 * {@link SecurityContextHolder} with the value returned by the
 * {@link SecurityContextRepository}. At the end of the {@link FilterChain} the
 * {@link SecurityContextPersistenceFilter} will clear out the
 * {@link SecurityContextHolder}. This means if we make multiple web requests, we will not
 * know which {@link SecurityContext} to use on subsequent requests.
 *
 * Typical usage is as follows:
 *
 * <ul>
 * <li>Before a test is executed, the {@link TestSecurityContextHolder} is populated.
 * Typically this is done using the
 * {@link org.springframework.security.test.context.support.WithSecurityContextTestExecutionListener}
 * </li>
 * <li>The test is ran. When used with {@link MockMvc} it is typically used with
 * {@link SecurityMockMvcRequestPostProcessors#testSecurityContext()}. Which ensures the
 * {@link SecurityContext} from {@link TestSecurityContextHolder} is properly
 * populated.</li>
 * <li>After the test is executed, the {@link TestSecurityContextHolder} and the
 * {@link SecurityContextHolder} are cleared out</li>
 * </ul>
 *
 * @author Rob Winch
 * @author Tadaya Tsuyukubo
 * @since 4.0
 *
 */
public final class TestSecurityContextHolder {

	private static final ThreadLocal<SecurityContext> contextHolder = new ThreadLocal<>();

	/**
	 * Clears the {@link SecurityContext} from {@link TestSecurityContextHolder} and
	 * {@link SecurityContextHolder}.
	 */
	public static void clearContext() {
		contextHolder.remove();
		SecurityContextHolder.clearContext();
	}

	/**
	 * Gets the {@link SecurityContext} from {@link TestSecurityContextHolder}.
	 * @return the {@link SecurityContext} from {@link TestSecurityContextHolder}.
	 */
	public static SecurityContext getContext() {
		SecurityContext ctx = contextHolder.get();

		if (ctx == null) {
			ctx = getDefaultContext();
			contextHolder.set(ctx);
		}

		return ctx;
	}

	/**
	 * Sets the {@link SecurityContext} on {@link TestSecurityContextHolder} and
	 * {@link SecurityContextHolder}.
	 * @param context the {@link SecurityContext} to use
	 */
	public static void setContext(SecurityContext context) {
		Assert.notNull(context, "Only non-null SecurityContext instances are permitted");
		contextHolder.set(context);
		SecurityContextHolder.setContext(context);
	}

	/**
	 * Creates a new {@link SecurityContext} with the given {@link Authentication}. The
	 * {@link SecurityContext} is set on {@link TestSecurityContextHolder} and
	 * {@link SecurityContextHolder}.
	 * @param authentication the {@link Authentication} to use
	 * @since 5.1.1
	 */
	public static void setAuthentication(Authentication authentication) {
		Assert.notNull(authentication, "Only non-null Authentication instances are permitted");
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		setContext(context);
	}

	/**
	 * Gets the default {@link SecurityContext} by delegating to the
	 * {@link SecurityContextHolder}
	 * @return the default {@link SecurityContext}
	 */
	private static SecurityContext getDefaultContext() {
		return SecurityContextHolder.getContext();
	}

	private TestSecurityContextHolder() {
	}

}
