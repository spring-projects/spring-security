/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.concurrent;

import static org.fest.assertions.Assertions.assertThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
@RunWith(MockitoJUnitRunner.class)
public class DelegatingSecurityContextRunnableTests {
    @Mock
    private Runnable delegate;
    @Mock
    private SecurityContext securityContext;
    @Mock
    private Object callableResult;

    private Runnable runnable;

    @Before
    public void setUp() throws Exception {
        doAnswer(new Answer<Object>() {
            public Object answer(InvocationOnMock invocation) throws Throwable {
                assertThat(SecurityContextHolder.getContext()).isEqualTo(securityContext);
                return null;
            }
        })
        .when(delegate).run();
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // --- constructor ---

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullDelegate() {
        new DelegatingSecurityContextRunnable(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullDelegateNonNullSecurityContext() {
        new DelegatingSecurityContextRunnable(null, securityContext);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullDelegateAndSecurityContext() {
        new DelegatingSecurityContextRunnable(null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullSecurityContext() {
        new DelegatingSecurityContextRunnable(delegate, null);
    }

    // --- run ---

    @Test
    public void call() throws Exception {
        runnable = new DelegatingSecurityContextRunnable(delegate, securityContext);
        runnable.run();
        assertWrapped();
    }

    @Test
    public void callDefaultSecurityContext() throws Exception {
        SecurityContextHolder.setContext(securityContext);
        runnable = new DelegatingSecurityContextRunnable(delegate);
        SecurityContextHolder.clearContext(); // ensure runnable is what sets up the SecurityContextHolder
        runnable.run();
        assertWrapped();
    }

    // --- create ---

    @Test(expected = IllegalArgumentException.class)
    public void createNullDelegate() {
        DelegatingSecurityContextRunnable.create(null, securityContext);
    }

    @Test(expected = IllegalArgumentException.class)
    public void createNullDelegateAndSecurityContext() {
        DelegatingSecurityContextRunnable.create(null, null);
    }

    @Test
    public void createNullSecurityContext() {
        SecurityContextHolder.setContext(securityContext);
        runnable = DelegatingSecurityContextRunnable.create(delegate, null);
        SecurityContextHolder.clearContext(); // ensure runnable is what sets up the SecurityContextHolder
        runnable.run();
        assertWrapped();
    }

    @Test
    public void create() {
        runnable = DelegatingSecurityContextRunnable.create(delegate, securityContext);
        runnable.run();
        assertWrapped();
    }

    private void assertWrapped() {
        verify(delegate).run();
        assertThat(SecurityContextHolder.getContext()).isEqualTo(SecurityContextHolder.createEmptyContext());
    }
}