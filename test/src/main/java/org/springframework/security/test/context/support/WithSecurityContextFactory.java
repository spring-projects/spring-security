/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.test.context.support;

import java.lang.annotation.Annotation;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.context.TestSecurityContextHolder;

/**
 * An API that works with WithUserTestExcecutionListener for creating a
 * {@link SecurityContext} that is populated in the {@link TestSecurityContextHolder}.
 *
 * @author Rob Winch
 *
 * @param <A>
 * @see WithSecurityContext
 * @see WithMockUser
 * @see WithUserDetails
 * @since 4.0
 */
public interface WithSecurityContextFactory<A extends Annotation> {

	/**
	 * Create a {@link SecurityContext} given an Annotation.
	 *
	 * @param annotation the {@link Annotation} to create the {@link SecurityContext}
	 * from. Cannot be null.
	 * @return the {@link SecurityContext} to use. Cannot be null.
	 */
	SecurityContext createSecurityContext(A annotation);
}