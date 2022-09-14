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

package org.springframework.security.core.context;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.Transient;

/**
 * A {@link SecurityContext} that is annotated with @{@link Transient} and thus should
 * never be stored across requests. This is useful in situations where one might run as a
 * different user for part of a request.
 *
 * @author Rob Winch
 * @since 5.7
 */
@Transient
public class TransientSecurityContext extends SecurityContextImpl {

	public TransientSecurityContext() {
	}

	public TransientSecurityContext(Authentication authentication) {
		super(authentication);
	}

}
