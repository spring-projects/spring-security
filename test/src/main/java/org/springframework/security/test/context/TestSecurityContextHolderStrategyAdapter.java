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

package org.springframework.security.test.context;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

public final class TestSecurityContextHolderStrategyAdapter implements SecurityContextHolderStrategy {

	@Override
	public void clearContext() {
		TestSecurityContextHolder.clearContext();
	}

	@Override
	public SecurityContext getContext() {
		return TestSecurityContextHolder.getContext();
	}

	@Override
	public void setContext(SecurityContext context) {
		TestSecurityContextHolder.setContext(context);
	}

	@Override
	public SecurityContext createEmptyContext() {
		return SecurityContextHolder.createEmptyContext();
	}

}
