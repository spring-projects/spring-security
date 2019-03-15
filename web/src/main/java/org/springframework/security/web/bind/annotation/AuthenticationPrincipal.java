/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.bind.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.core.Authentication;

/**
 * Annotation that binds a method parameter or method return value to the
 * {@link Authentication#getPrincipal()}. This is necessary to signal that the argument
 * should be resolved to the current user rather than a user that might be edited on a
 * form.
 *
 * @deprecated Use {@link org.springframework.security.core.annotation.AuthenticationPrincipal} instead.
 *
 * @author Rob Winch
 * @since 3.2
 */
@Target({ ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Deprecated
public @interface AuthenticationPrincipal {

	/**
	 * True if a {@link ClassCastException} should be thrown when the current
	 * {@link Authentication#getPrincipal()} is the incorrect type. Default is false.
	 *
	 * @return
	 */
	boolean errorOnInvalidType() default false;
}
