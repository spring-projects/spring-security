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

package net.sf.acegisecurity.attribute;

import org.aopalliance.intercept.Invocation;
import org.aopalliance.intercept.MethodInvocation;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;


/**
 * DOCUMENT ME!
 *
 * @author CameronBraid
 */
public class MockMethodInvocation implements MethodInvocation {
    //~ Methods ================================================================

    /* (non-Javadoc)
     * @see org.aopalliance.intercept.Invocation#setArgument(int, java.lang.Object)
     */
    public void setArgument(int arg0, Object arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.aopalliance.intercept.Invocation#getArgument(int)
     */
    public Object getArgument(int arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.aopalliance.intercept.Invocation#getArgumentCount()
     */
    public int getArgumentCount() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.aopalliance.intercept.Invocation#getArguments()
     */
    public Object[] getArguments() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.aopalliance.intercept.Invocation#getAttachment(java.lang.String)
     */
    public Object getAttachment(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.aopalliance.intercept.MethodInvocation#getMethod()
     */
    public Method getMethod() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.aopalliance.intercept.Joinpoint#getStaticPart()
     */
    public AccessibleObject getStaticPart() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.aopalliance.intercept.Joinpoint#getThis()
     */
    public Object getThis() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.aopalliance.intercept.Invocation#addAttachment(java.lang.String, java.lang.Object)
     */
    public Object addAttachment(String arg0, Object arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.aopalliance.intercept.Invocation#cloneInstance()
     */
    public Invocation cloneInstance() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.aopalliance.intercept.Joinpoint#proceed()
     */
    public Object proceed() throws Throwable {
        throw new UnsupportedOperationException("mock method not implemented");
    }
}
