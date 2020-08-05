/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.util;

import org.aopalliance.intercept.MethodInvocation;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;

/**
 * Represents the AOP Alliance <code>MethodInvocation</code>.
 *
 * @author Ben Alex
 */
public class SimpleMethodInvocation implements MethodInvocation {

	// ~ Instance fields
	// ================================================================================================

	private Method method;

	private Object[] arguments;

	private Object targetObject;

	// ~ Constructors
	// ===================================================================================================

	public SimpleMethodInvocation(Object targetObject, Method method, Object... arguments) {
		this.targetObject = targetObject;
		this.method = method;
		this.arguments = arguments == null ? new Object[0] : arguments;
	}

	public SimpleMethodInvocation() {
	}

	// ~ Methods
	// ========================================================================================================

	public Object[] getArguments() {
		return arguments;
	}

	public Method getMethod() {
		return method;
	}

	public AccessibleObject getStaticPart() {
		throw new UnsupportedOperationException("mock method not implemented");
	}

	public Object getThis() {
		return targetObject;
	}

	public Object proceed() {
		throw new UnsupportedOperationException("mock method not implemented");
	}

}
