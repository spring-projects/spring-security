/*
 * Copyright 2002-2015 the original author or authors.
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
package org.springframework.security.web.access.expression;

import org.junit.Before;
import org.junit.Test;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.FilterInvocation;

/**
 * @author Rob Winch
 *
 */
public class PathVariableSecurityEvaluationContextPostProcessorTests {
	PathVariableSecurityEvaluationContextPostProcessor processor;

	FilterInvocation invocation;

	MockHttpServletRequest request;
	MockHttpServletResponse response;
	StandardEvaluationContext context;

	@Before
	public void setup() {
		processor = new PathVariableSecurityEvaluationContextPostProcessor("/");

		request = new MockHttpServletRequest();
		request.setServletPath("/");
		response = new MockHttpServletResponse();
		invocation = new FilterInvocation(request,response, new MockFilterChain());
		context = new StandardEvaluationContext();
	}

	@Test
	public void queryIgnored() {
		request.setQueryString("logout");
		processor.postProcess(context, invocation);
	}

}
