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

package org.acegisecurity.adapters.jboss;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;


/**
 * Mocks a <code>javax.naming.Context</code> and returns an <code>Object</code>
 * when queried for address <code>java:comp/env/security/subject</code>.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MockInitialContext implements Context {
    //~ Instance fields ========================================================

    private Object object;

    //~ Constructors ===========================================================

    public MockInitialContext(Object object) {
        this.object = object;
    }

    private MockInitialContext() {
        super();
    }

    //~ Methods ================================================================

    public Hashtable getEnvironment() throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getNameInNamespace() throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public NameParser getNameParser(String name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public NameParser getNameParser(Name name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Object addToEnvironment(String propName, Object propVal)
        throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void bind(String name, Object obj) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void bind(Name name, Object obj) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void close() throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String composeName(String name, String prefix)
        throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Name composeName(Name name, Name prefix) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Context createSubcontext(String name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Context createSubcontext(Name name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void destroySubcontext(String name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void destroySubcontext(Name name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public NamingEnumeration list(String name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public NamingEnumeration list(Name name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public NamingEnumeration listBindings(String name)
        throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public NamingEnumeration listBindings(Name name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Object lookup(String name) throws NamingException {
        return this.object;
    }

    public Object lookup(Name name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Object lookupLink(String name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Object lookupLink(Name name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void rebind(String name, Object obj) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void rebind(Name name, Object obj) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Object removeFromEnvironment(String propName)
        throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void rename(String oldName, String newName)
        throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void rename(Name oldName, Name newName) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void unbind(String name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void unbind(Name name) throws NamingException {
        throw new UnsupportedOperationException("mock method not implemented");
    }
}
