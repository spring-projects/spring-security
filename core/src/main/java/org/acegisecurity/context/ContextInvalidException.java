/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

/**
 * Thrown if a {@link Context} is not valid, according to  {@link
 * Context#validate()}.
 *
 * @author Ben Alex
 * @version $Id$
 *
 * @see Context#validate()
 */
public class ContextInvalidException extends ContextException {
    //~ Constructors ===========================================================

    /**
     * Constructs a <code>ContextInvalidException</code> with the specified
     * message.
     *
     * @param msg the detail message.
     */
    public ContextInvalidException(String msg) {
        super(msg);
    }

    /**
     * Constructs a <code>ContextInvalidException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message.
     * @param t root cause
     */
    public ContextInvalidException(String msg, Throwable t) {
        super(msg, t);
    }
}
