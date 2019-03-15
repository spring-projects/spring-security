/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.config.method.sec2499;

import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.GenericXmlApplicationContext;

/**
 *
 * @author Rob Winch
 *
 */
public class Sec2499Tests {
	private GenericXmlApplicationContext parent;

	private GenericXmlApplicationContext child;

	@After
	public void cleanup() {
		if (parent != null) {
			parent.close();
		}
		if (child != null) {
			child.close();
		}
	}

	@Test
	public void methodExpressionHandlerInParentContextLoads() {
		parent = new GenericXmlApplicationContext(
				"org/springframework/security/config/method/sec2499/parent.xml");
		child = new GenericXmlApplicationContext();
		child.load("org/springframework/security/config/method/sec2499/child.xml");
		child.setParent(parent);
		child.refresh();
	}
}