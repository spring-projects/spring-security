/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

/**
 * Stores a {@link ConfigAttribute} as a <code>String</code>.
 *
 * @author <A HREF="mailto:ben.alex@fremerx.com">Ben Alex</A>
 * @version $Id$
 */
public class SecurityConfig implements ConfigAttribute {
    //~ Instance fields ========================================================

    private String attrib;

    //~ Constructors ===========================================================

    public SecurityConfig(String config) {
        this.attrib = config;
    }

    private SecurityConfig() {
        super();
    }

    //~ Methods ================================================================

    public String getAttribute() {
        return this.attrib;
    }

    public boolean equals(Object obj) {
        if (obj instanceof String) {
            return obj.equals(this.attrib);
        }

        if (obj instanceof ConfigAttribute) {
            ConfigAttribute attr = (ConfigAttribute) obj;

            return this.attrib.equals(attr.getAttribute());
        }

        return false;
    }

    public int hashCode() {
        return this.attrib.hashCode();
    }

    public String toString() {
        return this.attrib;
    }
}
