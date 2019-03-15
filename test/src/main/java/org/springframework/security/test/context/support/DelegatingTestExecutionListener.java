/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.test.context.support;

import org.springframework.test.context.TestContext;
import org.springframework.test.context.TestExecutionListener;
import org.springframework.test.context.support.AbstractTestExecutionListener;
import org.springframework.util.Assert;

/**
 * @author Rob Winch
 * @since 5.0
 */
class DelegatingTestExecutionListener
	extends AbstractTestExecutionListener {

	private final TestExecutionListener delegate;

	public DelegatingTestExecutionListener(TestExecutionListener delegate) {
		Assert.notNull(delegate, "delegate cannot be null");
		this.delegate = delegate;
	}

	@Override
	public void beforeTestClass(TestContext testContext) throws Exception {
		delegate.beforeTestClass(testContext);
	}

	@Override
	public void prepareTestInstance(TestContext testContext) throws Exception {
		delegate.prepareTestInstance(testContext);
	}

	@Override
	public void beforeTestMethod(TestContext testContext) throws Exception {
		delegate.beforeTestMethod(testContext);
	}

	@Override
	public void beforeTestExecution(TestContext testContext) throws Exception {
		delegate.beforeTestExecution(testContext);
	}

	@Override
	public void afterTestExecution(TestContext testContext) throws Exception {
		delegate.afterTestExecution(testContext);
	}

	@Override
	public void afterTestMethod(TestContext testContext) throws Exception {
		delegate.afterTestMethod(testContext);
	}

	@Override
	public void afterTestClass(TestContext testContext) throws Exception {
		delegate.afterTestClass(testContext);
	}
}
