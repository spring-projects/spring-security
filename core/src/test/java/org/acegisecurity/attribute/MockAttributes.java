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

import org.springframework.metadata.Attributes;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import java.util.Collection;


/**
 * DOCUMENT ME!
 *
 * @author CameronBraid
 */
public class MockAttributes implements Attributes {
    //~ Methods ================================================================

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.Class, java.lang.Class)
     */
    public Collection getAttributes(Class arg0, Class arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.Class)
     */
    public Collection getAttributes(Class arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.reflect.Field, java.lang.Class)
     */
    public Collection getAttributes(Field arg0, Class arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.reflect.Field)
     */
    public Collection getAttributes(Field arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.reflect.Method, java.lang.Class)
     */
    public Collection getAttributes(Method arg0, Class arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    /* (non-Javadoc)
     * @see org.springframework.metadata.Attributes#getAttributes(java.lang.reflect.Method)
     */
    public Collection getAttributes(Method arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }
}
