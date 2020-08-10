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
package org.springframework.security.test.context.showcase;

import org.springframework.security.test.context.support.WithSecurityContext;

/**
 * @author Rob Winch
 */
@WithSecurityContext(factory = WithMockCustomUserSecurityContextFactory.class)
public @interface WithMockCustomUser {

	/**
	 * The username to be used. The default is rob
	 * @return
	 */
	String username() default "rob";

	/**
	 * The roles to use. The default is "USER". A
	 * {@link org.springframework.security.core.GrantedAuthority} will be created for each
	 * value within roles. Each value in roles will automatically be prefixed with
	 * "ROLE_". For example, the default will result in "ROLE_USER" being used.
	 * @return
	 */
	String[] roles() default { "USER" };

	/**
	 * The name of the user
	 * @return
	 */
	String name() default "Rob Winch";

}
