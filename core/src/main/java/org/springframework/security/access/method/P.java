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
package org.springframework.security.access.method;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.core.parameters.AnnotationParameterNameDiscoverer;

/**
 * An annotation that can be used along with {@link AnnotationParameterNameDiscoverer} to
 * specify parameter names. This is useful for interfaces prior to JDK 8 which cannot
 * contain the parameter names.
 *
 * @see AnnotationParameterNameDiscoverer
 *
 * @author Rob Winch
 * @since 3.2
 * @deprecated use @{code org.springframework.security.core.parameters.P}
 */
@Target(ElementType.PARAMETER)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Deprecated
public @interface P {

	/**
	 * The parameter name
	 * @return
	 */
	String value();

}
