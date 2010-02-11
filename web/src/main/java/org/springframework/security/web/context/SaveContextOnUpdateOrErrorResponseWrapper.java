package org.springframework.security.web.context;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Base class for response wrappers which encapsulate the logic for storing a security context and which
 * store the with the <code>SecurityContext</code> when a <code>sendError()</code> or <code>sendRedirect</code>
 * happens. See issue SEC-398.
 * <p>
 * Sub-classes should implement the {@link #saveContext(SecurityContext context)} method.
 * <p>
 * Support is also provided for disabling URL rewriting
 *
 * @author Luke Taylor
 * @author Marten Algesten
 * @since 3.0
 */
public abstract class SaveContextOnUpdateOrErrorResponseWrapper extends HttpServletResponseWrapper {

    private boolean contextSaved = false;
    /* See SEC-1052 */
    private boolean disableUrlRewriting;

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
     * Tells if the response wrapper has called <code>saveContext()</code> because of an error or redirect.
     */
    public final boolean isContextSaved() {
        return contextSaved;
    }

}
