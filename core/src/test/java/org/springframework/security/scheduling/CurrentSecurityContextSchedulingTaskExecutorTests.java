package org.springframework.security.scheduling;

import org.junit.Before;
import org.springframework.security.core.context.SecurityContext;

/**
 * Tests using the current {@link SecurityContext} on {@link DelegatingSecurityContextSchedulingTaskExecutor}
 *
 * @author Rob Winch
 * @since 3.2
 *
 */
public class CurrentSecurityContextSchedulingTaskExecutorTests extends AbstractSecurityContextSchedulingTaskExecutorTests {

    @Before
    public void setUp() throws Exception {
        currentSecurityContextPowermockSetup();
    }

    protected DelegatingSecurityContextSchedulingTaskExecutor create() {
        return new DelegatingSecurityContextSchedulingTaskExecutor(taskExecutorDelegate);
    }
}
