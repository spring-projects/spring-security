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

package org.springframework.security.access.intercept.aopalliance;

import java.lang.reflect.Method;

import junit.framework.TestCase;

import org.springframework.security.TargetObject;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityInterceptor;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSourceEditor;

/**
 * Tests {@link MethodSecurityMetadataSourceAdvisor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
@SuppressWarnings("deprecation")
public class MethodSecurityMetadataSourceAdvisorTests extends TestCase {
    //~ Methods ========================================================================================================

    private MethodSecurityInterceptor getInterceptor() {
        MethodSecurityMetadataSourceEditor editor = new MethodSecurityMetadataSourceEditor();
        editor.setAsText("org.springframework.security.TargetObject.countLength=ROLE_NOT_USED");

        MapBasedMethodSecurityMetadataSource map = (MapBasedMethodSecurityMetadataSource) editor.getValue();

        MethodSecurityInterceptor msi = new MethodSecurityInterceptor();
        msi.setSecurityMetadataSource(map);

        return msi;
    }

    public void testAdvisorReturnsFalseWhenMethodInvocationNotDefined()
        throws Exception {
        Class<TargetObject> clazz = TargetObject.class;
        Method method = clazz.getMethod("makeLowerCase", new Class[] {String.class});

        MethodSecurityMetadataSourceAdvisor advisor = new MethodSecurityMetadataSourceAdvisor(getInterceptor());
        assertFalse(advisor.getPointcut().getMethodMatcher().matches(method, clazz));
    }

    public void testAdvisorReturnsTrueWhenMethodInvocationIsDefined()
        throws Exception {
        Class<TargetObject> clazz = TargetObject.class;
        Method method = clazz.getMethod("countLength", new Class[] {String.class});

        MethodSecurityMetadataSourceAdvisor advisor = new MethodSecurityMetadataSourceAdvisor(getInterceptor());
        assertTrue(advisor.getPointcut().getMethodMatcher().matches(method, clazz));
    }

    public void testDetectsImproperlyConfiguredAdvice() {
        MethodSecurityInterceptor msi = new MethodSecurityInterceptor();

        try {
            new MethodSecurityMetadataSourceAdvisor(msi);
            fail("Should have detected null SecurityMetadataSource and thrown AopConfigException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testUnsupportedOperations() throws Throwable {
        Class<TargetObject> clazz = TargetObject.class;
        Method method = clazz.getMethod("countLength", new Class[] {String.class});

        MethodSecurityMetadataSourceAdvisor.InternalMethodInvocation imi = new MethodSecurityMetadataSourceAdvisor(getInterceptor()).new InternalMethodInvocation(method, clazz);

        try {
            imi.getArguments();
            fail("Should have thrown UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            assertTrue(true);
        }

        try {
            imi.getStaticPart();
            fail("Should have thrown UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            assertTrue(true);
        }

        try {
            imi.proceed();
            fail("Should have thrown UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            assertTrue(true);
        }

        try {
            new MethodSecurityMetadataSourceAdvisor(getInterceptor()).new InternalMethodInvocation();
            fail("Should have thrown UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            assertTrue(true);
        }
    }
}
