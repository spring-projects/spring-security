/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.adapters;

import net.sf.acegisecurity.Authentication;


/**
 * Indicates a specialized, immutable, server-side only {@link Authentication}
 * class.
 * 
 * <P>
 * Automatically considered valid by the {@link AuthByAdapterProvider},
 * provided the hash code presented by the implementation objects matches that
 * expected by the <code>AuthByAdapterProvider</code>.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AuthByAdapter extends Authentication {
    //~ Methods ================================================================

    /**
     * DOCUMENT ME!
     *
     * @return the hash code of the key used when the object was created.
     */
    public int getKeyHash();
}
