package org.springframework.security.acls.domain;

import org.springframework.security.acls.AclFormattingUtils;
import org.springframework.security.acls.Permission;

/**
 * Provides an abstract superclass for {@link Permission} implementations.
 * 
 * @author Ben Alex
 * @since 2.0.3
 * @see AbstractRegisteredPermission
 * 
 */
public abstract class AbstractPermission implements Permission {

    //~ Instance fields ================================================================================================

    protected char code;
    protected int mask;

    //~ Constructors ===================================================================================================

    protected AbstractPermission(int mask, char code) {
        this.mask = mask;
        this.code = code;
    }

    //~ Methods ========================================================================================================

    public final boolean equals(Object arg0) {
        if (arg0 == null) {
            return false;
        }

        if (!(arg0 instanceof Permission)) {
            return false;
        }

        Permission rhs = (Permission) arg0;

        return (this.mask == rhs.getMask());
    }

    public final int getMask() {
        return mask;
    }

    public String getPattern() {
        return AclFormattingUtils.printBinary(mask, code);
    }

    public final String toString() {
        return this.getClass().getSimpleName() + "[" + getPattern() + "=" + mask + "]";
    }

    public final int hashCode() {
        return this.mask;
    }
}
