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

import java.io.IOException;
import java.io.PrintWriter;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;


/**
 * Mocks a <code>HttpServletResponse</code>, recording the
 * <code>sendRedirect</code> URL and <code>sendError</code> code.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class MockHttpServletResponse implements HttpServletResponse {
    //~ Instance fields ========================================================

    private Map headersMap = new HashMap();
    private String redirect;
    private int error;

    //~ Methods ================================================================

    public void setBufferSize(int arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public int getBufferSize() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getCharacterEncoding() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public boolean isCommitted() {
        if (redirect == null) {
            return false;
        } else {
            return true;
        }
    }

    public void setContentLength(int arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void setContentType(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void setDateHeader(String arg0, long arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public int getError() {
        return this.error;
    }

    public void setHeader(String arg0, String arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getHeader(String arg0) {
        Object result = headersMap.get(arg0);

        if (result != null) {
            return (String) headersMap.get(arg0);
        } else {
            return null;
        }
    }

    public void setIntHeader(String arg0, int arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void setLocale(Locale arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public Locale getLocale() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public ServletOutputStream getOutputStream() throws IOException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String getRedirect() {
        return redirect;
    }

    public void setStatus(int arg0, String arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void setStatus(int arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public PrintWriter getWriter() throws IOException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void addCookie(Cookie arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void addDateHeader(String arg0, long arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void addHeader(String arg0, String arg1) {
        headersMap.put(arg0, arg1);
    }

    public void addIntHeader(String arg0, int arg1) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public boolean containsHeader(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String encodeRedirectURL(String arg0) {
        return arg0;
    }

    public String encodeRedirectUrl(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String encodeURL(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public String encodeUrl(String arg0) {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void flushBuffer() throws IOException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void reset() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void resetBuffer() {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void sendError(int arg0, String arg1) throws IOException {
        throw new UnsupportedOperationException("mock method not implemented");
    }

    public void sendError(int arg0) throws IOException {
        this.error = arg0;
    }

    public void sendRedirect(String arg0) throws IOException {
        this.redirect = arg0;
    }
}
