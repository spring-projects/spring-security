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

package org.springframework.security.intercept.method.aopalliance;

import junit.framework.TestCase;

import org.springframework.security.TargetObject;

import org.springframework.security.intercept.method.MethodDefinitionMap;
import org.springframework.security.intercept.method.MethodDefinitionSourceEditor;

import org.springframework.aop.framework.AopConfigException;

import java.lang.reflect.Method;


/**
 * Tests {@link MethodDefinitionSourceAdvisor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MethodDefinitionSourceAdvisorTests extends TestCase {
    //~ Constructors ===================================================================================================

    public MethodDefinitionSourceAdvisorTests() {
        super();
    }

    public MethodDefinitionSourceAdvisorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    private MethodSecurityInterceptor getInterceptor() {
        MethodDefinitionSourceEditor editor = new MethodDefinitionSourceEditor();
        editor.setAsText("org.springframework.security.TargetObject.countLength=ROLE_NOT_USED");

        MethodDefinitionMap map = (MethodDefinitionMap) editor.getValue();

        MethodSecurityInterceptor msi = new MethodSecurityInterceptor();
        msi.setObjectDefinitionSource(map);

        return msi;
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(MethodDefinitionSourceAdvisorTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testAdvisorReturnsFalseWhenMethodInvocationNotDefined()
        throws Exception {
        Class clazz = TargetObject.class;
        Method method = clazz.getMethod("makeLowerCase", new Class[] {String.class});

        MethodDefinitionSourceAdvisor advisor = new MethodDefinitionSourceAdvisor(getInterceptor());
        assertFalse(advisor.getPointcut().getMethodMatcher().matches(method, clazz));
    }

    public void testAdvisorReturnsTrueWhenMethodInvocationIsDefined()
        throws Exception {
        Class clazz = TargetObject.class;
        Method method = clazz.getMethod("countLength", new Class[] {String.class});

        MethodDefinitionSourceAdvisor advisor = new MethodDefinitionSourceAdvisor(getInterceptor());
        assertTrue(advisor.getPointcut().getMethodMatcher().matches(method, clazz));
    }

    public void testDetectsImproperlyConfiguredAdvice() {
        MethodSecurityInterceptor msi = new MethodSecurityInterceptor();

        try {
            new MethodDefinitionSourceAdvisor(msi);
            fail("Should have detected null ObjectDefinitionSource and thrown AopConfigException");
        } catch (AopConfigException expected) {
            assertTrue(true);
        }
    }

    public void testUnsupportedOperations() throws Throwable {
        Class clazz = TargetObject.class;
        Method method = clazz.getMethod("countLength", new Class[] {String.class});

        MethodDefinitionSourceAdvisor.InternalMethodInvocation imi = new MethodDefinitionSourceAdvisor(getInterceptor()).new InternalMethodInvocation(method);

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
            imi.getThis();
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
            new MethodDefinitionSourceAdvisor(getInterceptor()).new InternalMethodInvocation();
            fail("Should have thrown UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            assertTrue(true);
        }
    }
}
