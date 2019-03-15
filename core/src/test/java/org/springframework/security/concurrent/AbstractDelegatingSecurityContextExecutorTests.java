/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.concurrent;

import static org.mockito.Mockito.verify;

import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;

import org.junit.Test;
import org.mockito.Mock;

/**
 * Abstract class for testing {@link DelegatingSecurityContextExecutor} which allows customization of
 * how {@link DelegatingSecurityContextExecutor} and its mocks are created.
 *
 * @author Rob Winch
 * @since 3.2
 * @see CurrentDelegatingSecurityContextExecutorTests
 * @see ExplicitDelegatingSecurityContextExecutorTests
 */
public abstract class AbstractDelegatingSecurityContextExecutorTests extends AbstractDelegatingSecurityContextTestSupport {
    @Mock
    protected ScheduledExecutorService delegate;

    private DelegatingSecurityContextExecutor executor;

    // --- constructor ---

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullDelegate() {
        new DelegatingSecurityContextExecutor(null);
    }

    // --- execute ---

    @Test
    public void execute() {
        executor = create();
        executor.execute(runnable);
        verify(getExecutor()).execute(wrappedRunnable);
    }

    protected Executor getExecutor() {
        return delegate;
    }

    protected abstract DelegatingSecurityContextExecutor create();
}
