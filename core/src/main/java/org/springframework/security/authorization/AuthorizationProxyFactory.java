/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authorization;

/**
 * A factory for wrapping arbitrary objects in authorization-related advice
 *
 * @author Josh Cummings
 * @since 6.3
 * @see org.springframework.security.authorization.method.AuthorizationAdvisorProxyFactory
 */
public interface AuthorizationProxyFactory {

	/**
	 * Wrap the given {@code object} in authorization-related advice.
	 *
	 * <p>
	 * Please check the implementation for which kinds of objects it supports.
	 * @param object the object to proxy
	 * @return the proxied object
	 * @throws org.springframework.aop.framework.AopConfigException if a proxy cannot be
	 * created
	 */
	Object proxy(Object object);

}
