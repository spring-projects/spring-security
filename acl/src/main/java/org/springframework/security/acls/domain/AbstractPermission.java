package org.springframework.security.acls.domain;

import org.springframework.security.acls.model.Permission;

/**
 * Provides an abstract superclass for {@link Permission} implementations.
 *
 * @author Ben Alex
 * @since 2.0.3
 */
public abstract class AbstractPermission implements Permission {

    //~ Instance fields ================================================================================================

    protected char code;
    protected int mask;

    //~ Constructors ===================================================================================================
    /**
     * Sets the permission mask and uses the '*' character to represent active bits when represented as a bit
     * pattern string.
     *
     * @param mask the integer bit mask for the permission
     */
    protected AbstractPermission(int mask) {
        this.mask = mask;
        this.code = '*';
    }

    /**
     * Sets the permission mask and uses the specified character for active bits.
     *
     * @param mask the integer bit mask for the permission
     * @param code the character to print for each active bit in the mask (see {@link Permission#getPattern()})
     */
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
