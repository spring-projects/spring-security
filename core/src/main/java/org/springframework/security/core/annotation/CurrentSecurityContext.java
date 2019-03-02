/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.core.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that is used to resolve {@link SecurityContext#getAuthentication()} to a method
 * argument.
 *
 * @author Dan Zheng
 * @since 5.2
 *
 * See: <a href=
 * "{@docRoot}/org/springframework/security/web/bind/support/CurrentSecurityContextArgumentResolver.html"
 * > CurrentSecurityContextArgumentResolver </a>
 */
@Target({ ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CurrentSecurityContext {
	/**
	 * True if a {@link ClassCastException} should be thrown when the current
	 * {@link SecurityContext} is the incorrect type. Default is false.
	 *
	 * @return
	 */
	boolean errorOnInvalidType() default false;

	/**
	 * If specified will use the provided SpEL expression to resolve the security context. This
	 * is convenient if users need to transform the result.
	 *
	 * <pre>
	 * &#64;CurrentSecurityContext(expression = "authentication") Authentication authentication
	 * </pre>
	 *
	 * <p>
	 *    if you want to retrieve more object from the authentcation, you can see the following the expression
	 * </p>
	 *
	 * <pre>
	 * &#64;CurrentSecurityContext(expression = "authentication.principal") Object principal
	 * </pre>
	 *
	 * @return the expression to use.
	 */
	String expression() default "";
}
