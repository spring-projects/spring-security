/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.vote;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;

import org.aopalliance.intercept.MethodInvocation;


/**
 * Indicates a class is responsible for voting on authorization decisions.
 * 
 * <p>
 * The coordination of voting (ie polling <code>AccessDecisionVoter</code>s,
 * tallying their responses, and making the final authorization decision) is
 * performed by an {@link net.sf.acegisecurity.AccessDecisionManager}.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AccessDecisionVoter {
    //~ Static fields/initializers =============================================

    public static final int ACCESS_GRANTED = 1;
    public static final int ACCESS_ABSTAIN = 0;
    public static final int ACCESS_DENIED = -1;

    //~ Methods ================================================================

    /**
     * Indicates whether this <code>AccessDecisionVoter</code> is able to vote
     * on the passed <code>ConfigAttribute</code>.
     * 
     * <p>
     * This allows the <code>SecurityInterceptor</code> to check every
     * configuration attribute can be consumed by the configured
     * <code>AccessDecisionManager</code> and/or <code>RunAsManager</code>.
     * </p>
     *
     * @param attribute a configuration attribute that has been configured
     *        against the <code>SecurityInterceptor</code>
     *
     * @return true if this <code>AccessDecisionVoter</code> can support the
     *         passed configuration attribute
     */
    public boolean supports(ConfigAttribute attribute);

    /**
     * Indicates whether or not access is granted.
     * 
     * <p>
     * The decision must be affirmative (<code>ACCESS_GRANTED</code>),
     * negative (<code>ACCESS_DENIED</code>) or the
     * <code>AccessDecisionVoter</code> can abstain
     * (<code>ACCESS_ABSTAIN</code>) from voting. Under no circumstances
     * should implementing classes return any other value. If a weighting of
     * results is desired, this should be handled in a custom  {@link
     * net.sf.acegisecurity.AccessDecisionManager} instead.
     * </p>
     * 
     * <P>
     * Unless an <code>AccessDecisionVoter</code> is specifically intended to
     * vote on an access control decision due to a passed method invocation or
     * configuration attribute parameter, it must return
     * <code>ACCESS_ABSTAIN</code>. This prevents the coordinating
     * <code>AccessDecisionManager</code> from counting votes from those
     * <code>AccessDecisionVoter</code>s without a legitimate interest in the
     * access control decision.
     * </p>
     * 
     * <p>
     * Whilst the method invocation is passed as a parameter to maximise
     * flexibility in making access control decisions, implementing classes
     * must never modify the behaviour of the method invocation (such as
     * calling <Code>MethodInvocation.proceed()</code>).
     * </p>
     *
     * @param authentication the caller invoking the method
     * @param invocation the method being called
     * @param config the configuration attributes associated with the method
     *        being invoked
     *
     * @return either {@link #ACCESS_GRANTED}, {@link #ACCESS_ABSTAIN} or
     *         {@link #ACCESS_DENIED}
     */
    public int vote(Authentication authentication, MethodInvocation invocation,
                    ConfigAttributeDefinition config);
}
