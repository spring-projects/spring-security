/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.context;

import junit.framework.TestCase;

import net.sf.acegisecurity.context.security.SecureContextImpl;

import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.PropertiesBeanDefinitionReader;

import java.util.Properties;


/**
 * Tests {@link ContextInterceptor}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContextInterceptorTests extends TestCase {
    //~ Constructors ===========================================================

    public ContextInterceptorTests() {
        super();
    }

    public ContextInterceptorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ContextInterceptorTests.class);
    }

    public ITargetObject makeInterceptedTarget() {
        String PREFIX = "beans.";
        DefaultListableBeanFactory lbf = new DefaultListableBeanFactory();
        Properties p = new Properties();
        p.setProperty(PREFIX + "contextInterceptor.class",
            "net.sf.acegisecurity.context.ContextInterceptor");
        p.setProperty(PREFIX + "targetObject.class",
            "net.sf.acegisecurity.context.TargetObject");
        p.setProperty(PREFIX + "target.class",
            "org.springframework.aop.framework.ProxyFactoryBean");
        p.setProperty(PREFIX + "target.proxyInterfaces",
            "net.sf.acegisecurity.context.ITargetObject");
        p.setProperty(PREFIX + "target.interceptorNames",
            "contextInterceptor,targetObject");

        int count = (new PropertiesBeanDefinitionReader(lbf))
            .registerBeanDefinitions(p, PREFIX);

        return (ITargetObject) lbf.getBean("target");
    }

    public void testInterceptorDetectsEmptyContextHolder()
        throws Exception {
        ITargetObject target = makeInterceptedTarget();

        try {
            target.makeUpperCase("hello");
            fail("Should have thrown ContextHolderEmptyException");
        } catch (ContextHolderEmptyException expected) {
            assertTrue(true);
        }
    }

    public void testInterceptorDetectsInvalidContext()
        throws Exception {
        ITargetObject target = makeInterceptedTarget();
        ContextHolder.setContext(new SecureContextImpl()); // Authentication not set

        try {
            target.makeUpperCase("hello");
            fail("Should have thrown ContextInvalidException");
        } catch (ContextInvalidException expected) {
            assertTrue(true);
        }
    }

    public void testInterceptorNormalOperation() throws Exception {
        ITargetObject target = makeInterceptedTarget();
        ContextHolder.setContext(new ContextImpl());

        String result = target.makeUpperCase("hello");
        assertEquals("HELLO", result);
    }
}
