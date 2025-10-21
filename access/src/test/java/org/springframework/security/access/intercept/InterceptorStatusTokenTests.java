/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.access.intercept;

import java.util.List;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.Test;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.util.SimpleMethodInvocation;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link InterceptorStatusToken}.
 *
 * @author Ben Alex
 */
public class InterceptorStatusTokenTests {

	@Test
	public void testOperation() {
		List<ConfigAttribute> attr = SecurityConfig.createList("FOO");
		MethodInvocation mi = new SimpleMethodInvocation();
		SecurityContext ctx = SecurityContextHolder.createEmptyContext();
		InterceptorStatusToken token = new InterceptorStatusToken(ctx, true, attr, mi);
		assertThat(token.isContextHolderRefreshRequired()).isTrue();
		assertThat(token.getAttributes()).isEqualTo(attr);
		assertThat(token.getSecureObject()).isEqualTo(mi);
		assertThat(token.getSecurityContext()).isSameAs(ctx);
	}

}
