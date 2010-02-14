package org.springframework.security.acls.model;

/**
 * Abstract base class for Acl data operations.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public abstract class AclDataAccessException extends RuntimeException {

    /**
     * Constructs an <code>AclDataAccessException</code> with the specified
     * message and root cause.
     *
     * @param msg the detail message
     * @param cause the root cause
     */
    public AclDataAccessException(String msg, Throwable cause) {
        super(msg, cause);
    }

    /**
     * Constructs an <code>AclDataAccessException</code> with the specified
     * message and no root cause.
     *
     * @param msg the detail message
     */
    public AclDataAccessException(String msg) {
        super(msg);
    }
}
