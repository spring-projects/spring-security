/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

import java.io.Serializable;


/**
 * Holds objects that are needed on every request.
 * 
 * <P>
 * A <code>Context</code> will be sent between application tiers  via a  {@link
 * ContextHolder}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface Context extends Serializable {
    //~ Methods ================================================================

    /**
     * Check the <code>Context</code> is properly configured.
     * 
     * <P>
     * This allows implementations to confirm they are valid, as this method
     * is automatically called by the {@link ContextInterceptor}.
     * </p>
     *
     * @throws ContextInvalidException if the <code>Context</code> is invalid.
     */
    public void validate() throws ContextInvalidException;
}
