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

package net.sf.acegisecurity;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpSessionContext;


/**
 * Mocks a <code>HttpSession</code> and provides the
 * <code>getAttribute()</code> and <code>setAttribute()</code> methods.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MockHttpSession implements HttpSession {
    //~ Instance fields ========================================================

    private Map map = new HashMap();

    //~ Methods ================================================================

    public void setAttribute(String arg0, Object arg1) {
        map.put(arg0, arg1);
    }

    public Object getAttribute(String arg0) {
        return map.get(arg0);
    }

    public Enumeration getAttributeNames() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public long getCreationTime() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getId() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public long getLastAccessedTime() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void setMaxInactiveInterval(int arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public int getMaxInactiveInterval() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public boolean isNew() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public ServletContext getServletContext() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public HttpSessionContext getSessionContext() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Object getValue(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String[] getValueNames() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void invalidate() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void putValue(String arg0, Object arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void removeAttribute(String arg0) {
        map.remove(arg0);
    }

    public void removeValue(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }
}
