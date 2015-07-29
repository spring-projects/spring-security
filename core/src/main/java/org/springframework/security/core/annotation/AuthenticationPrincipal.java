/*
 * Copyright 2002-2013 the original author or authors.
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

import org.springframework.security.core.Authentication;

/**
 * Annotation that is used to resolve {@link Authentication#getPrincipal()} to a method
 * argument.
 *
 * @author Rob Winch
 * @since 4.0
 *
 *  See: <a href="{@docRoot}/org/springframework/security/messaging/context/AuthenticationPrincipalArgumentResolver.html">
 *  AuthenticationPrincipalArgumentResolver
 *  </a>
 */
@Target({ ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuthenticationPrincipal {

	/**
	 * True if a {@link ClassCastException} should be thrown when the current
	 * {@link Authentication#getPrincipal()} is the incorrect type. Default is false.
	 *
	 * @return
	 */
	boolean errorOnInvalidType() default false;
}
