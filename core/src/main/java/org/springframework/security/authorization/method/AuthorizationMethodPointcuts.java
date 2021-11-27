/*
 * Copyright 2002-2021 the original author or authors.
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

import java.lang.annotation.Annotation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.Pointcuts;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;

/**
 * @author Josh Cummings
 */
final class AuthorizationMethodPointcuts {

	@SafeVarargs
	static Pointcut forAnnotations(Class<? extends Annotation>... annotations) {
		ComposablePointcut pointcut = null;
		for (Class<? extends Annotation> annotation : annotations) {
			if (pointcut == null) {
				pointcut = new ComposablePointcut(classOrMethod(annotation));
			}
			else {
				pointcut.union(classOrMethod(annotation));
			}
		}
		return pointcut;
	}

	private static Pointcut classOrMethod(Class<? extends Annotation> annotation) {
		return Pointcuts.union(new AnnotationMatchingPointcut(null, annotation, true),
				new AnnotationMatchingPointcut(annotation, true));
	}

	private AuthorizationMethodPointcuts() {

	}

}
