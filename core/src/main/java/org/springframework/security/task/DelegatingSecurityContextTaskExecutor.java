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
package org.springframework.security.task;

import org.springframework.core.task.TaskExecutor;
import org.springframework.security.concurrent.DelegatingSecurityContextExecutor;
import org.springframework.security.concurrent.DelegatingSecurityContextRunnable;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * An {@link TaskExecutor} which wraps each {@link Runnable} in a
 * {@link DelegatingSecurityContextRunnable}.
 *
 * @author Rob Winch
 * @since 3.2
 */
public class DelegatingSecurityContextTaskExecutor extends DelegatingSecurityContextExecutor implements TaskExecutor {

	/**
	 * Creates a new {@link DelegatingSecurityContextTaskExecutor} that uses the specified
	 * {@link SecurityContext}.
	 * @param delegateTaskExecutor the {@link TaskExecutor} to delegate to. Cannot be
	 * null.
	 * @param securityContext the {@link SecurityContext} to use for each
	 * {@link DelegatingSecurityContextRunnable}
	 */
	public DelegatingSecurityContextTaskExecutor(TaskExecutor delegateTaskExecutor, SecurityContext securityContext) {
		super(delegateTaskExecutor, securityContext);
	}

	/**
	 * Creates a new {@link DelegatingSecurityContextTaskExecutor} that uses the current
	 * {@link SecurityContext} from the {@link SecurityContextHolder}.
	 * @param delegate the {@link TaskExecutor} to delegate to. Cannot be null.
	 */
	public DelegatingSecurityContextTaskExecutor(TaskExecutor delegate) {
		this(delegate, null);
	}

}