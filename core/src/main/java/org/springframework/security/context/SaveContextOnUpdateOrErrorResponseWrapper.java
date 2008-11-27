package org.springframework.security.context;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

/**
 * Base class for response wrappers which encapsulate the logic for storing a security context and which
 * store the with the <code>SecurityContext</code> when a <code>sendError()</code> or <code>sendRedirect</code>
 * happens. See SEC-398.
 * <p>
 * Sub-classes should implement the {@link #saveContext(SecurityContext context)} method.
 *
 * @author Luke Taylor
 * @author Marten Algesten
 * @version $Id$
 * @since 2.5
 */
abstract class SaveContextOnUpdateOrErrorResponseWrapper extends HttpServletResponseWrapper {

    boolean contextSaved = false;

    SaveContextOnUpdateOrErrorResponseWrapper(HttpServletResponse response) {
        super(response);
    }

    /**
     * Implements the logic for storing the security context.
     *
     * @param context the <tt>SecurityContext</tt> instance to store
     */
    abstract void saveContext(SecurityContext context);

    /**
     * Makes sure the session is updated before calling the
     * superclass <code>sendError()</code>
     */
    public void sendError(int sc) throws IOException {
        doSaveContext();
        super.sendError(sc);
    }

    /**
     * Makes sure the session is updated before calling the
     * superclass <code>sendError()</code>
     */
    public void sendError(int sc, String msg) throws IOException {
        doSaveContext();
        super.sendError(sc, msg);
    }

    /**
     * Makes sure the context is stored before calling the
     * superclass <code>sendRedirect()</code>
     */
    public void sendRedirect(String location) throws IOException {
        doSaveContext();
        super.sendRedirect(location);
    }

    /**
     * Calls <code>saveContext()</code> with the current contents of the <tt>SecurityContextHolder</tt>.
     */
    private void doSaveContext() {
        saveContext(SecurityContextHolder.getContext());
        contextSaved = true;
    }

    /**
     * Tells if the response wrapper has called <code>saveContext()</code> because of an error or redirect.
     */
    public boolean isContextSaved() {
        return contextSaved;
    }

}
