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
package org.springframework.security.integration.python;

import org.python.util.PythonInterpreter;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.PrePostInvocationAttributeFactory;

public class PythonInterpreterPrePostInvocationAttributeFactory implements
		PrePostInvocationAttributeFactory {

	public PythonInterpreterPrePostInvocationAttributeFactory() {
		PythonInterpreter.initialize(System.getProperties(), null, new String[] {});
	}

	public PreInvocationAttribute createPreInvocationAttribute(String preFilterAttribute,
			String filterObject, String preAuthorizeAttribute) {
		return new PythonInterpreterPreInvocationAttribute(preAuthorizeAttribute);
	}

	public PostInvocationAttribute createPostInvocationAttribute(
			String postFilterAttribute, String postAuthorizeAttribute) {
		return null;
	}
}
