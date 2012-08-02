/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.web.context;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Base class for response wrappers which encapsulate the logic for storing a security context and which
 * store the <code>SecurityContext</code> when a <code>sendError()</code>, <code>sendRedirect</code>,
 * <code>getOutputStream().close()</code>, <code>getOutputStream().flush()</code>, <code>getWriter().close()</code>, or
 * <code>getWriter().flush()</code> happens. See issue SEC-398 and SEC-2005.
 * <p>
 * Sub-classes should implement the {@link #saveContext(SecurityContext context)} method.
 * <p>
 * Support is also provided for disabling URL rewriting
 *
 * @author Luke Taylor
 * @author Marten Algesten
 * @author Rob Winch
 * @since 3.0
 */
public abstract class SaveContextOnUpdateOrErrorResponseWrapper extends HttpServletResponseWrapper {

    private boolean contextSaved = false;
    /* See SEC-1052 */
    private final boolean disableUrlRewriting;

    /**
     * @param response              the response to be wrapped
     * @param disableUrlRewriting   turns the URL encoding methods into null operations, preventing the use
     *                              of URL rewriting to add the session identifier as a URL parameter.
     */
    public SaveContextOnUpdateOrErrorResponseWrapper(HttpServletResponse response, boolean disableUrlRewriting) {
        super(response);
        this.disableUrlRewriting = disableUrlRewriting;
    }

    /**
     * Implements the logic for storing the security context.
     *
     * @param context the <tt>SecurityContext</tt> instance to store
     */
    protected abstract void saveContext(SecurityContext context);

    /**
     * Makes sure the session is updated before calling the
     * superclass <code>sendError()</code>
     */
    @Override
    public final void sendError(int sc) throws IOException {
        doSaveContext();
        super.sendError(sc);
    }

    /**
     * Makes sure the session is updated before calling the
     * superclass <code>sendError()</code>
     */
    @Override
    public final void sendError(int sc, String msg) throws IOException {
        doSaveContext();
        super.sendError(sc, msg);
    }

    /**
     * Makes sure the context is stored before calling the
     * superclass <code>sendRedirect()</code>
     */
    @Override
    public final void sendRedirect(String location) throws IOException {
        doSaveContext();
        super.sendRedirect(location);
    }

    /**
     * Makes sure the context is stored before calling <code>getOutputStream().close()</code> or
     * <code>getOutputStream().flush()</code>
     */
    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        return new SaveContextServletOutputStream(super.getOutputStream());
    }

    /**
     * Makes sure the context is stored before calling <code>getWriter().close()</code> or
     * <code>getWriter().flush()</code>
     */
    @Override
    public PrintWriter getWriter() throws IOException {
        return new SaveContextPrintWriter(super.getWriter());
    }

    /**
     * Makes sure the context is stored before calling the
     * superclass <code>flushBuffer()</code>
     */
    @Override
    public void flushBuffer() throws IOException {
        doSaveContext();
        super.flushBuffer();
    }

    /**
     * Calls <code>saveContext()</code> with the current contents of the <tt>SecurityContextHolder</tt>.
     */
    private void doSaveContext() {
        saveContext(SecurityContextHolder.getContext());
        contextSaved = true;
    }

    @Override
    public final String encodeRedirectUrl(String url) {
        if (disableUrlRewriting) {
            return url;
        }
        return super.encodeRedirectUrl(url);
    }

    @Override
    public final String encodeRedirectURL(String url) {
        if (disableUrlRewriting) {
            return url;
        }
        return super.encodeRedirectURL(url);
    }

    @Override
    public final String encodeUrl(String url) {
        if (disableUrlRewriting) {
            return url;
        }
        return super.encodeUrl(url);
    }

    @Override
    public final String encodeURL(String url) {
        if (disableUrlRewriting) {
            return url;
        }
        return super.encodeURL(url);
    }

    /**
     * Tells if the response wrapper has called <code>saveContext()</code> because of this wrapper.
     */
    public final boolean isContextSaved() {
        return contextSaved;
    }

    /**
     * Ensures the {@link SecurityContext} is updated prior to methods that commit the response.
     * @author Rob Winch
     */
    private class SaveContextPrintWriter extends PrintWriter {

        public SaveContextPrintWriter(Writer out) {
            super(out);
        }

        public void flush() {
            doSaveContext();
            super.flush();
        }

        public void close() {
            doSaveContext();
            super.close();
        }
    }

    /**
     * Ensures the {@link SecurityContext} is updated prior to methods that commit the response.
     *
     * @author Rob Winch
     */
    private class SaveContextServletOutputStream extends ServletOutputStream {
        private final ServletOutputStream delegate;

        public SaveContextServletOutputStream(ServletOutputStream delegate) {
            this.delegate = delegate;
        }

        public void write(int b) throws IOException {
            this.delegate.write(b);
        }

        @Override
        public void flush() throws IOException {
            doSaveContext();
            super.flush();
        }

        @Override
        public void close() throws IOException {
            doSaveContext();
            super.close();
        }
    }
}
