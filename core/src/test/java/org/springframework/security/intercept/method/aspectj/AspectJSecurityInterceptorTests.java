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

package org.springframework.security.intercept.method.aspectj;

import java.lang.reflect.Method;

import junit.framework.TestCase;

import org.springframework.security.AccessDeniedException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.MockAccessDecisionManager;
import org.springframework.security.MockApplicationEventPublisher;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.MockJoinPoint;
import org.springframework.security.MockRunAsManager;
import org.springframework.security.TargetObject;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.intercept.method.MapBasedMethodDefinitionSource;
import org.springframework.security.intercept.method.MethodDefinitionSourceEditor;
import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.util.AuthorityUtils;


/**
 * Tests {@link AspectJSecurityInterceptor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class AspectJSecurityInterceptorTests extends TestCase {
    //~ Constructors ===================================================================================================

    public AspectJSecurityInterceptorTests() {
    }

    public AspectJSecurityInterceptorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    protected void tearDown() throws Exception {
        super.tearDown();
        SecurityContextHolder.clearContext();
    }

    public void testCallbackIsInvokedWhenPermissionGranted() throws Exception {
        AspectJSecurityInterceptor si = new AspectJSecurityInterceptor();
        si.setApplicationEventPublisher(new MockApplicationEventPublisher(true));
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setRunAsManager(new MockRunAsManager());

        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText("org.springframework.security.TargetObject.countLength=MOCK_ONE,MOCK_TWO");

        MapBasedMethodDefinitionSource map = (MapBasedMethodDefinitionSource) editor.getValue();
        si.setObjectDefinitionSource(map);
        assertEquals(map, si.getObjectDefinitionSource());

        si.afterPropertiesSet();

        Class clazz = TargetObject.class;
        Method method = clazz.getMethod("countLength", new Class[] {String.class});
        MockJoinPoint joinPoint = new MockJoinPoint(new TargetObject(), method);

        MockAspectJCallback aspectJCallback = new MockAspectJCallback();

        SecurityContextHolder.getContext()
                             .setAuthentication(new TestingAuthenticationToken("rod", "koala",
                new GrantedAuthority[] {new GrantedAuthorityImpl("MOCK_ONE")}));

        Object result = si.invoke(joinPoint, aspectJCallback);

        assertEquals("object proceeded", result);
    }

    public void testCallbackIsNotInvokedWhenPermissionDenied() throws Exception {
        AspectJSecurityInterceptor si = new AspectJSecurityInterceptor();
        si.setApplicationEventPublisher(new MockApplicationEventPublisher(true));
        si.setAccessDecisionManager(new MockAccessDecisionManager());
        si.setAuthenticationManager(new MockAuthenticationManager());
        si.setRunAsManager(new MockRunAsManager());

        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText("org.springframework.security.TargetObject.countLength=MOCK_ONE,MOCK_TWO");

        MapBasedMethodDefinitionSource map = (MapBasedMethodDefinitionSource) editor.getValue();
        si.setObjectDefinitionSource(map);

        si.afterPropertiesSet();

        Class clazz = TargetObject.class;
        Method method = clazz.getMethod("countLength", new Class[] {String.class});
        MockJoinPoint joinPoint = new MockJoinPoint(new TargetObject(), method);

        MockAspectJCallback aspectJCallback = new MockAspectJCallback();
        aspectJCallback.setThrowExceptionIfInvoked(true);

        SecurityContextHolder.getContext()
                             .setAuthentication(new TestingAuthenticationToken("rod", "koala",
                AuthorityUtils.NO_AUTHORITIES ));

        try {
            si.invoke(joinPoint, aspectJCallback);
            fail("Should have thrown AccessDeniedException");
        } catch (AccessDeniedException expected) {
            assertTrue(true);
        }
    }

    //~ Inner Classes ==================================================================================================

    private class MockAspectJCallback implements AspectJCallback {
        private boolean throwExceptionIfInvoked = false;

        private MockAspectJCallback() {}

        public Object proceedWithObject() {
            if (throwExceptionIfInvoked) {
                throw new IllegalStateException("AspectJCallback proceeded");
            }

            return "object proceeded";
        }

        public void setThrowExceptionIfInvoked(boolean throwExceptionIfInvoked) {
            this.throwExceptionIfInvoked = throwExceptionIfInvoked;
        }
    }
}
