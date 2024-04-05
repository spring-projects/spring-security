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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for specifying handling behavior when an authorization denied happens in
 * method security
 *
 * @author Marcus da Coregio
 * @since 6.3
 * @see org.springframework.security.access.prepost.PreAuthorize
 * @see org.springframework.security.access.prepost.PostAuthorize
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface AuthorizationDeniedHandler {

	/**
	 * The {@link MethodAuthorizationDeniedHandler} used to handle denied authorizations
	 * from {@link org.springframework.security.access.prepost.PreAuthorize}
	 * @return
	 */
	Class<? extends MethodAuthorizationDeniedHandler> handlerClass() default ThrowingMethodAuthorizationDeniedHandler.class;

	/**
	 * The {@link MethodAuthorizationDeniedPostProcessor} used to post process denied
	 * authorizations from
	 * {@link org.springframework.security.access.prepost.PostAuthorize}
	 * @return
	 */
	Class<? extends MethodAuthorizationDeniedPostProcessor> postProcessorClass() default ThrowingMethodAuthorizationDeniedPostProcessor.class;

}
