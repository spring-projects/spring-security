/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package sample.contact;

/**
 * An object that represents user-editable sections of a {@link Contact}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class WebContact {
    //~ Instance fields ========================================================

    private String email;
    private String name;

    //~ Methods ================================================================

    public void setEmail(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
