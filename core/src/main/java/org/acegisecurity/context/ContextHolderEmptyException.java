/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

/**
 * Thrown if a {@link ContextHolder} object does not contain a valid  {@link
 * Context}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ContextHolderEmptyException extends ContextException {
    //~ Constructors ===========================================================

    /**
     * Constructs a <code>ContextHolderEmptyException</code> with the specified
     * message.
     *
     * @param msg the detail message
     */
    public ContextHolderEmptyException(String msg) {
        super(msg);
    }

    /**
     * Constructs a <code>ContextHolderEmptyException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message
     * @param t root cause
     */
    public ContextHolderEmptyException(String msg, Throwable t) {
        super(msg, t);
    }
}
