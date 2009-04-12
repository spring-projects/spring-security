/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.access.intercept;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.Test;
import org.springframework.security.AuthenticationManager;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.intercept.SecurityMetadataSource;
import org.springframework.security.util.SimpleMethodInvocation;


/**
 * Tests some {@link AbstractSecurityInterceptor} methods. Most of the  testing for this class is found in the
 * <code>MethodSecurityInterceptorTests</code> class.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AbstractSecurityInterceptorTests {
    private Mockery jmock = new JUnit4Mockery();

    //~ Methods ========================================================================================================

    @Test(expected=IllegalArgumentException.class)
    public void detectsIfInvocationPassedIncompatibleSecureObject() throws Exception {
        MockSecurityInterceptorWhichOnlySupportsStrings si = new MockSecurityInterceptorWhichOnlySupportsStrings();

        si.setRunAsManager(jmock.mock(RunAsManager.class));
        si.setAuthenticationManager(jmock.mock(AuthenticationManager.class));
        si.setAfterInvocationManager(jmock.mock(AfterInvocationManager.class));
        si.setAccessDecisionManager(jmock.mock(AccessDecisionManager.class));
        si.setSecurityMetadataSource(jmock.mock(SecurityMetadataSource.class));

        jmock.checking(new Expectations() {{ ignoring(anything()); }});
        si.beforeInvocation(new SimpleMethodInvocation());
    }

    @Test(expected=IllegalArgumentException.class)
    public void detectsViolationOfGetSecureObjectClassMethod() throws Exception {
        MockSecurityInterceptorReturnsNull si = new MockSecurityInterceptorReturnsNull();
        si.setRunAsManager(jmock.mock(RunAsManager.class));
        si.setAuthenticationManager(jmock.mock(AuthenticationManager.class));
        si.setAfterInvocationManager(jmock.mock(AfterInvocationManager.class));
        si.setAccessDecisionManager(jmock.mock(AccessDecisionManager.class));
        si.setSecurityMetadataSource(jmock.mock(SecurityMetadataSource.class));

        jmock.checking(new Expectations() {{ ignoring(anything()); }});

        si.afterPropertiesSet();
    }

    //~ Inner Classes ==================================================================================================

    private class MockSecurityInterceptorReturnsNull extends AbstractSecurityInterceptor {
        private SecurityMetadataSource securityMetadataSource;

        public Class<? extends Object> getSecureObjectClass() {
            return null;
        }

        public SecurityMetadataSource obtainSecurityMetadataSource() {
            return securityMetadataSource;
        }

        public void setSecurityMetadataSource(SecurityMetadataSource securityMetadataSource) {
            this.securityMetadataSource = securityMetadataSource;
        }
    }

    private class MockSecurityInterceptorWhichOnlySupportsStrings extends AbstractSecurityInterceptor {
        private SecurityMetadataSource securityMetadataSource;

        public Class<? extends Object> getSecureObjectClass() {
            return String.class;
        }

        public SecurityMetadataSource obtainSecurityMetadataSource() {
            return securityMetadataSource;
        }

        public void setSecurityMetadataSource(SecurityMetadataSource securityMetadataSource) {
            this.securityMetadataSource = securityMetadataSource;
        }
    }
}
