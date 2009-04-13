package org.springframework.security.acls;

import org.springframework.core.NestedRuntimeException;

/**
 * Abstract superclass for all exceptions thrown in the acls package and subpackages.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
public abstract class AclException extends NestedRuntimeException {

    /**
     * Constructs an <code>AclException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message
     * @param t the root cause
     */
    public AclException(String msg, Throwable cause) {
        super(msg, cause);
    }

    /**
     * Constructs an <code>AclException</code> with the specified
     * message and no root cause.
     *
     * @param msg the detail message
     */
    public AclException(String msg) {
        super(msg);
    }
}
