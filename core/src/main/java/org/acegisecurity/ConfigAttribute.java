/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity;

/**
 * Stores a security system related configuration attribute.
 * 
 * <p>
 * When the {@link SecurityInterceptor} is setup, a list of configuration
 * attributes is defined for secure method patterns. These configuration
 * attributes have special meaning to a {@link RunAsManager}, {@link
 * AccessDecisionManager} or <code>AccessDecisionManager</code> delegate.
 * </p>
 * 
 * <P>
 * Stored at runtime with other <code>ConfigAttribute</code>s for the same
 * method within a {@link ConfigAttributeDefinition}.
 * </p>
 *
 * @author <A HREF="mailto:ben.alex@fremerx.com">Ben Alex</A>
 * @version $Id$
 */
public interface ConfigAttribute {
    //~ Methods ================================================================

    /**
     * If the <code>ConfigAttribute</code> can be represented as a
     * <code>String</code> and that <code>String</code> is sufficient in
     * precision to be relied upon as a configuration parameter by a {@link
     * RunAsManager}, {@link AccessDecisionManager} or
     * <code>AccessDecisionManager</code> delegate, this method should  return
     * such a <code>String</code>.
     * 
     * <p>
     * If the <code>ConfigAttribute</code> cannot be expressed with sufficient
     * precision as a <code>String</code>,  <code>null</code> should be
     * returned. Returning <code>null</code> will require an relying classes
     * to specifically support the  <code>ConfigAttribute</code>
     * implementation, so returning  <code>null</code> should be avoided
     * unless actually  required.
     * </p>
     *
     * @return a representation of the configuration attribute (or
     *         <code>null</code> if the configuration attribute cannot be
     *         expressed as a <code>String</code> with sufficient precision).
     */
    public String getAttribute();
}
