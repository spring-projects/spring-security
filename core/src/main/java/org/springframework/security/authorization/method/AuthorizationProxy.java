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

package org.springframework.security.authorization.method;

import org.springframework.aop.RawTargetAccess;

/**
 * An interface that is typically implemented by Spring Security's AOP support to identify
 * an instance as being proxied by Spring Security.
 *
 * <p>
 * Also provides a way to access the underlying target object, handy for working with the
 * object without invoking the authorization rules.
 *
 * <p>
 * This can be helpful when taking working with a proxied object and needing to hand it to
 * a layer of the application that should not invoke the rules, like a Spring Data
 * repository:
 *
 * <pre>
 *	MyObject object = this.objectRepository.findById(123L); // now an authorized proxy
 *  object.setProtectedValue(...); // only works if authorized
 *  if (object instanceof AuthorizationProxy proxy) {
 *  	// Spring Data wants to be able to persist the entire object
 *  	// so we'll remove the proxy
 *      object = (MyObject) proxy.toAuthorizedTarget();
 *  }
 *  this.objectRepository.save(object);
 * </pre>
 *
 * @author Josh Cummings
 * @since 6.4
 */
public interface AuthorizationProxy extends RawTargetAccess {

	/**
	 * Access underlying target object
	 * @return the target object
	 */
	Object toAuthorizedTarget();

}
