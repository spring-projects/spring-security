/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.ui.rmi;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.MockMethodInvocation;
import net.sf.acegisecurity.TargetObject;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContext;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.aopalliance.intercept.MethodInvocation;

import java.lang.reflect.Method;


/**
 * Tests {@link ContextPropagatingRemoteInvocation} and {@link
 * ContextPropagatingRemoteInvocationFactory}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContextPropagatingRemoteInvocationTests extends TestCase {
    //~ Constructors ===========================================================

    public ContextPropagatingRemoteInvocationTests() {
        super();
    }

    public ContextPropagatingRemoteInvocationTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(ContextPropagatingRemoteInvocationTests.class);
    }

    public void testNormalOperation() throws Exception {
        // Setup client-side context
        SecureContext clientSideContext = new SecureContextImpl();
        Authentication clientSideAuthentication = new UsernamePasswordAuthenticationToken("marissa",
                "koala");
        clientSideContext.setAuthentication(clientSideAuthentication);
        ContextHolder.setContext(clientSideContext);

        ContextPropagatingRemoteInvocation remoteInvocation = getRemoteInvocation();

        // Set to null, as ContextPropagatingRemoteInvocation already obtained
        // a copy and nulling is necessary to ensure the Context delivered by
        // ContextPropagatingRemoteInvocation is used on server-side
        ContextHolder.setContext(null);

        // The result from invoking the TargetObject should contain the
        // Authentication class delivered via the ContextHolder
        assertEquals("some_string net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken false",
            remoteInvocation.invoke(new TargetObject()));
    }

    public void testNullContextHolderDoesNotCauseInvocationProblems()
        throws Exception {
        ContextHolder.setContext(null); // just to be explicit

        ContextPropagatingRemoteInvocation remoteInvocation = getRemoteInvocation();
        ContextHolder.setContext(null); // unnecessary, but for explicitness

        assertEquals("some_string ContextHolder Not Security Aware",
            remoteInvocation.invoke(new TargetObject()));
    }

    private ContextPropagatingRemoteInvocation getRemoteInvocation()
        throws Exception {
        Class clazz = TargetObject.class;
        Method method = clazz.getMethod("makeLowerCase",
                new Class[] {String.class});
        MethodInvocation mi = new MockMethodInvocation(method,
                new Object[] {"SOME_STRING"});

        ContextPropagatingRemoteInvocationFactory factory = new ContextPropagatingRemoteInvocationFactory();

        return (ContextPropagatingRemoteInvocation) factory
        .createRemoteInvocation(mi);
    }
}
