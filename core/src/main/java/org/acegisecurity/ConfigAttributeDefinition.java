/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


/**
 * Holds a group of {@link ConfigAttribute}s that are associated with a given
 * method.
 * 
 * <p>
 * All the <code>ConfigAttributeDefinition</code>s associated with a given
 * <code>SecurityInterceptor</code> are stored in a  {@link
 * MethodDefinitionMap}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class ConfigAttributeDefinition {
    //~ Instance fields ========================================================

    private Set configAttributes = new HashSet();

    //~ Constructors ===========================================================

    public ConfigAttributeDefinition() {
        super();
    }

    //~ Methods ================================================================

    /**
     * DOCUMENT ME!
     *
     * @return all the configuration attributes related to the method.
     */
    public Iterator getConfigAttributes() {
        return this.configAttributes.iterator();
    }

    /**
     * Adds a <code>ConfigAttribute</code> that is related to the method.
     *
     * @param newConfigAttribute DOCUMENT ME!
     */
    public void addConfigAttribute(ConfigAttribute newConfigAttribute) {
        this.configAttributes.add(newConfigAttribute);
    }

    public String toString() {
        return this.configAttributes.toString();
    }
}
