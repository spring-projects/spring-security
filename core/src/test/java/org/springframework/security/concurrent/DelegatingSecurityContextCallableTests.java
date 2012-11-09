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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.concurrent.Callable;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.internal.stubbing.answers.Returns;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 *
 * @author Rob Winch
 * @since 3.2
 */
@RunWith(MockitoJUnitRunner.class)
public class DelegatingSecurityContextCallableTests {
    @Mock
    private Callable<Object> delegate;
    @Mock
    private SecurityContext securityContext;
    @Mock
    private Object callableResult;

    private Callable<Object> callable;

    @Before
    @SuppressWarnings("serial")
    public void setUp() throws Exception {
        when(delegate.call()).thenAnswer(new Returns(callableResult) {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                assertThat(SecurityContextHolder.getContext()).isEqualTo(securityContext);
                return super.answer(invocation);
            }
        });
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    // --- constructor ---

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullDelegate() {
        new DelegatingSecurityContextCallable<Object>(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullDelegateNonNullSecurityContext() {
        new DelegatingSecurityContextCallable<Object>(null, securityContext);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullDelegateAndSecurityContext() {
        new DelegatingSecurityContextCallable<Object>(null, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullSecurityContext() {
        new DelegatingSecurityContextCallable<Object>(delegate, null);
    }

    // --- call ---

    @Test
    public void call() throws Exception {
        callable = new DelegatingSecurityContextCallable<Object>(delegate, securityContext);
        assertWrapped(callable.call());
    }

    @Test
    public void callDefaultSecurityContext() throws Exception {
        SecurityContextHolder.setContext(securityContext);
        callable = new DelegatingSecurityContextCallable<Object>(delegate);
        SecurityContextHolder.clearContext(); // ensure callable is what sets up the SecurityContextHolder
        assertWrapped(callable.call());
    }

    // --- create ---

    @Test(expected = IllegalArgumentException.class)
    public void createNullDelegate() {
        DelegatingSecurityContextCallable.create(null, securityContext);
    }

    @Test(expected = IllegalArgumentException.class)
    public void createNullDelegateAndSecurityContext() {
        DelegatingSecurityContextRunnable.create(null, null);
    }

    @Test
    public void createNullSecurityContext() throws Exception {
        SecurityContextHolder.setContext(securityContext);
        callable = DelegatingSecurityContextCallable.create(delegate, null);
        SecurityContextHolder.clearContext(); // ensure callable is what sets up the SecurityContextHolder
        assertWrapped(callable.call());
    }

    @Test
    public void create() throws Exception {
        callable = DelegatingSecurityContextCallable.create(delegate, securityContext);
        assertWrapped(callable.call());
    }

    private void assertWrapped(Object actualResult) throws Exception {
        assertThat(actualResult).isEqualTo(callableResult);
        verify(delegate).call();
        assertThat(SecurityContextHolder.getContext()).isEqualTo(SecurityContextHolder.createEmptyContext());
    }
}