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
import java.util.Locale;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Base class for response wrappers which encapsulate the logic for storing a security context and which store the
 * <code>SecurityContext</code> when a <code>sendError()</code>, <code>sendRedirect</code>,
 * <code>getOutputStream().close()</code>, <code>getOutputStream().flush()</code>, <code>getWriter().close()</code>, or
 * <code>getWriter().flush()</code> happens on the same thread that this
 * {@link SaveContextOnUpdateOrErrorResponseWrapper} was created. See issue SEC-398 and SEC-2005.
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
    private final Log logger = LogFactory.getLog(getClass());

    private boolean disableSaveOnResponseCommitted;

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
     * Invoke this method to disable automatic saving of the
     * {@link SecurityContext} when the {@link HttpServletResponse} is
     * committed. This can be useful in the event that Async Web Requests are
     * made which may no longer contain the {@link SecurityContext} on it.
     */
    public void disableSaveOnResponseCommitted() {
        this.disableSaveOnResponseCommitted = true;
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
     * Calls <code>saveContext()</code> with the current contents of the
     * <tt>SecurityContextHolder</tt> as long as
     * {@link #disableSaveOnResponseCommitted()()} was not invoked.
     */
    private void doSaveContext() {
        if(!disableSaveOnResponseCommitted) {
            saveContext(SecurityContextHolder.getContext());
            contextSaved = true;
        } else if(logger.isDebugEnabled()){
            logger.debug("Skip saving SecurityContext since saving on response commited is disabled");
        }
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
     * Ensures the {@link SecurityContext} is updated prior to methods that commit the response. We delegate all methods
     * to the original {@link PrintWriter} to ensure that the behavior is as close to the original {@link PrintWriter}
     * as possible. See SEC-2039
     * @author Rob Winch
     */
    private class SaveContextPrintWriter extends PrintWriter {
        private final PrintWriter delegate;

        public SaveContextPrintWriter(PrintWriter delegate) {
            super(delegate);
            this.delegate = delegate;
        }

        public void flush() {
            doSaveContext();
            delegate.flush();
        }

        public void close() {
            doSaveContext();
            delegate.close();
        }

        public int hashCode() {
            return delegate.hashCode();
        }

        public boolean equals(Object obj) {
            return delegate.equals(obj);
        }

        public String toString() {
            return getClass().getName() + "[delegate=" + delegate.toString() + "]";
        }

        public boolean checkError() {
            return delegate.checkError();
        }

        public void write(int c) {
            delegate.write(c);
        }

        public void write(char[] buf, int off, int len) {
            delegate.write(buf, off, len);
        }

        public void write(char[] buf) {
            delegate.write(buf);
        }

        public void write(String s, int off, int len) {
            delegate.write(s, off, len);
        }

        public void write(String s) {
            delegate.write(s);
        }

        public void print(boolean b) {
            delegate.print(b);
        }

        public void print(char c) {
            delegate.print(c);
        }

        public void print(int i) {
            delegate.print(i);
        }

        public void print(long l) {
            delegate.print(l);
        }

        public void print(float f) {
            delegate.print(f);
        }

        public void print(double d) {
            delegate.print(d);
        }

        public void print(char[] s) {
            delegate.print(s);
        }

        public void print(String s) {
            delegate.print(s);
        }

        public void print(Object obj) {
            delegate.print(obj);
        }

        public void println() {
            delegate.println();
        }

        public void println(boolean x) {
            delegate.println(x);
        }

        public void println(char x) {
            delegate.println(x);
        }

        public void println(int x) {
            delegate.println(x);
        }

        public void println(long x) {
            delegate.println(x);
        }

        public void println(float x) {
            delegate.println(x);
        }

        public void println(double x) {
            delegate.println(x);
        }

        public void println(char[] x) {
            delegate.println(x);
        }

        public void println(String x) {
            delegate.println(x);
        }

        public void println(Object x) {
            delegate.println(x);
        }

        public PrintWriter printf(String format, Object... args) {
            return delegate.printf(format, args);
        }

        public PrintWriter printf(Locale l, String format, Object... args) {
            return delegate.printf(l, format, args);
        }

        public PrintWriter format(String format, Object... args) {
            return delegate.format(format, args);
        }

        public PrintWriter format(Locale l, String format, Object... args) {
            return delegate.format(l, format, args);
        }

        public PrintWriter append(CharSequence csq) {
            return delegate.append(csq);
        }

        public PrintWriter append(CharSequence csq, int start, int end) {
            return delegate.append(csq, start, end);
        }

        public PrintWriter append(char c) {
            return delegate.append(c);
        }
    }

    /**
     * Ensures the {@link SecurityContext} is updated prior to methods that commit the response. We delegate all methods
     * to the original {@link ServletOutputStream} to ensure that the behavior is as close to the original {@link ServletOutputStream}
     * as possible. See SEC-2039
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

        public void flush() throws IOException {
            doSaveContext();
            delegate.flush();
        }

        public void close() throws IOException {
            doSaveContext();
            delegate.close();
        }

        public int hashCode() {
            return delegate.hashCode();
        }

        public boolean equals(Object obj) {
            return delegate.equals(obj);
        }

        public void print(boolean b) throws IOException {
            delegate.print(b);
        }

        public void print(char c) throws IOException {
            delegate.print(c);
        }

        public void print(double d) throws IOException {
            delegate.print(d);
        }

        public void print(float f) throws IOException {
            delegate.print(f);
        }

        public void print(int i) throws IOException {
            delegate.print(i);
        }

        public void print(long l) throws IOException {
            delegate.print(l);
        }

        public void print(String arg0) throws IOException {
            delegate.print(arg0);
        }

        public void println() throws IOException {
            delegate.println();
        }

        public void println(boolean b) throws IOException {
            delegate.println(b);
        }

        public void println(char c) throws IOException {
            delegate.println(c);
        }

        public void println(double d) throws IOException {
            delegate.println(d);
        }

        public void println(float f) throws IOException {
            delegate.println(f);
        }

        public void println(int i) throws IOException {
            delegate.println(i);
        }

        public void println(long l) throws IOException {
            delegate.println(l);
        }

        public void println(String s) throws IOException {
            delegate.println(s);
        }

        public void write(byte[] b) throws IOException {
            delegate.write(b);
        }

        public void write(byte[] b, int off, int len) throws IOException {
            delegate.write(b, off, len);
        }

        public String toString() {
            return getClass().getName() + "[delegate=" + delegate.toString() + "]";
        }
    }
}
