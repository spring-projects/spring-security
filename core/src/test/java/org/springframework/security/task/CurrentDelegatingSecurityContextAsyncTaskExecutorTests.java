package org.springframework.security.task;

import org.junit.Before;


/**
 * Tests using the current {@link SecurityContext} on {@link DelegatingSecurityContextAsyncTaskExecutor}
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
public class CurrentDelegatingSecurityContextAsyncTaskExecutorTests extends
        AbstractDelegatingSecurityContextAsyncTaskExecutorTests {

    @Before
    public void setUp() throws Exception {
        currentSecurityContextPowermockSetup();
    }

    @Override
    protected DelegatingSecurityContextAsyncTaskExecutor create() {
        return new DelegatingSecurityContextAsyncTaskExecutor(taskExecutorDelegate);
    }

}
