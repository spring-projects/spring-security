/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

import org.springframework.core.NestedRuntimeException;


/**
 * Abstract superclass for all exceptions thrown in the context package and
 * subpackages.
 *
 * <p>
 * Note that this is a runtime (unchecked) exception.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public abstract class ContextException extends NestedRuntimeException {
    //~ Constructors ===========================================================

    /**
     * Constructs a <code>ContextException</code> with the specified message
     * and root cause.
     *
     * @param msg the detail message
     * @param t the root cause
     */
    public ContextException(String msg, Throwable t) {
        super(msg, t);
    }

    /**
     * Constructs a <code>ContextException</code> with the specified message
     * and no root cause.
     *
     * @param msg the detail message
     */
    public ContextException(String msg) {
        super(msg);
    }
}
