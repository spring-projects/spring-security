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

package org.springframework.security;

/**
 * Simply extends {@link TargetObject} so we have a different object to put configuration
 * attributes against.
 * <P>
 * There is no different behaviour. We have to define each method so that
 * <code>Class.getMethod(methodName, args)</code> returns a <code>Method</code>
 * referencing this class rather than the parent class.
 * </p>
 * <P>
 * We need to implement <code>ITargetObject</code> again because the
 * <code>MethodDefinitionAttributes</code> only locates attributes on interfaces
 * explicitly defined by the intercepted class (not the interfaces defined by its parent
 * class or classes).
 * </p>
 *
 * @author Ben Alex
 */
public class OtherTargetObject extends TargetObject implements ITargetObject {

	// ~ Methods
	// ========================================================================================================

	public String makeLowerCase(String input) {
		return super.makeLowerCase(input);
	}

	public String makeUpperCase(String input) {
		return super.makeUpperCase(input);
	}

	public String publicMakeLowerCase(String input) {
		return super.publicMakeLowerCase(input);
	}

}
