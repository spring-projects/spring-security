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
package org.springframework.security.access.prepost;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for specifying a method filtering expression which will be evaluated before
 * a method has been invoked. The name of the argument to be filtered is specified using
 * the <tt>filterTarget</tt> attribute. This must be a Java Collection implementation
 * which supports the {@link java.util.Collection#remove(Object) remove} method.
 * Pre-filtering isn't supported on array types and will fail if the value of named filter
 * target argument is null at runtime.
 * <p>
 * For methods which have a single argument which is a collection type, this argument will
 * be used as the filter target.
 * <p>
 * The annotation value contains the expression which will be evaluated for each element
 * in the collection. If the expression evaluates to false, the element will be removed.
 * The reserved name "filterObject" can be used within the expression to refer to the
 * current object which is being evaluated.
 *
 * @author Luke Taylor
 * @since 3.0
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface PreFilter {
	/**
	 * @return the Spring-EL expression to be evaluated before invoking the protected
	 * method
	 */
	public String value();

	/**
	 * @return the name of the parameter which should be filtered (must be a non-null
	 * collection instance) If the method contains a single collection argument, then this
	 * attribute can be omitted.
	 */
	public String filterTarget() default "";
}
