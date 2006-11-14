package org.acegisecurity.annotation;

/**
 *
 * @author Joe Scalise
 */
public class Department extends Entity {
    //~ Instance fields ========================================================

    private boolean active = true;

    //~ Constructors ===========================================================

    public Department(String name) {
        super(name);
    }

    //~ Methods ================================================================

    public boolean isActive() {
        return this.active;
    }

    void deactive() {
        this.active = true;
    }

}
