/*
 * Copyright 2002-2015 the original author or authors.
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

package org.springframework.security.web.access.expression;

import java.util.Collections;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.FilterInvocation;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 *
 */
public class AbstractVariableEvaluationContextPostProcessorTests {

	static final String KEY = "a";
	static final String VALUE = "b";

	VariableEvaluationContextPostProcessor processor;

	FilterInvocation invocation;

	MockHttpServletRequest request;

	MockHttpServletResponse response;

	EvaluationContext context;

	@BeforeEach
	public void setup() {
		this.processor = new VariableEvaluationContextPostProcessor();
		this.request = new MockHttpServletRequest();
		this.request.setServletPath("/");
		this.response = new MockHttpServletResponse();
		this.invocation = new FilterInvocation(this.request, this.response, new MockFilterChain());
		this.context = new StandardEvaluationContext();
	}

	@Test
	public void extractVariables() {
		this.context = this.processor.postProcess(this.context, this.invocation);
		assertThat(this.context.lookupVariable(KEY)).isEqualTo(VALUE);
	}

	@Test
	public void extractVariablesOnlyUsedOnce() {
		this.context = this.processor.postProcess(this.context, this.invocation);
		assertThat(this.context.lookupVariable(KEY)).isEqualTo(VALUE);
		this.processor.results = Collections.emptyMap();
		assertThat(this.context.lookupVariable(KEY)).isEqualTo(VALUE);
	}

	static class VariableEvaluationContextPostProcessor extends AbstractVariableEvaluationContextPostProcessor {

		Map<String, String> results = Collections.singletonMap(KEY, VALUE);

		@Override
		protected Map<String, String> extractVariables(HttpServletRequest request) {
			return this.results;
		}

	}

}
