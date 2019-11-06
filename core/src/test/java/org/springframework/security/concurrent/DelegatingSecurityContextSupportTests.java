/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.concurrent;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.security.core.context.SecurityContext;

/**
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
public class DelegatingSecurityContextSupportTests extends
		AbstractDelegatingSecurityContextTestSupport {
	private AbstractDelegatingSecurityContextSupport support;

	@Test
	public void wrapCallable() throws Exception {
		explicitSecurityContextPowermockSetup();
		support = new ConcreteDelegatingSecurityContextSupport(securityContext);
		assertThat(support.wrap(callable)).isSameAs(wrappedCallable);
		assertThat(securityContextCaptor.getValue()).isSameAs(securityContext);
	}

	@Test
	public void wrapCallableNullSecurityContext() throws Exception {
		currentSecurityContextPowermockSetup();
		support = new ConcreteDelegatingSecurityContextSupport(null);
		assertThat(support.wrap(callable)).isSameAs(wrappedCallable);
	}

	@Test
	public void wrapRunnable() throws Exception {
		explicitSecurityContextPowermockSetup();
		support = new ConcreteDelegatingSecurityContextSupport(securityContext);
		assertThat(support.wrap(runnable)).isSameAs(wrappedRunnable);
		assertThat(securityContextCaptor.getValue()).isSameAs(securityContext);
	}

	@Test
	public void wrapRunnableNullSecurityContext() throws Exception {
		currentSecurityContextPowermockSetup();
		support = new ConcreteDelegatingSecurityContextSupport(null);
		assertThat(support.wrap(runnable)).isSameAs(wrappedRunnable);
	}

	private static class ConcreteDelegatingSecurityContextSupport extends
			AbstractDelegatingSecurityContextSupport {
		ConcreteDelegatingSecurityContextSupport(SecurityContext securityContext) {
			super(securityContext);
		}
	}
}
