package org.springframework.security.access.prepost;

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * Voter which performs the actions using a PreInvocationAuthorizationAdvice implementation
 * generated from @PreFilter and @PreAuthorize annotations.
 * <p>
 * In practice, if these annotations are being used, they will normally contain all the necessary
 * access control logic, so a voter-based system is not really necessary and a single <tt>AccessDecisionManager</tt>
 * which contained the same logic would suffice. However, this class fits in readily with the traditional
 * voter-based <tt>AccessDecisionManager</tt> implementations used by Spring Security.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class PreInvocationAuthorizationAdviceVoter implements AccessDecisionVoter {
    protected final Log logger = LogFactory.getLog(getClass());

    private PreInvocationAuthorizationAdvice preAdvice;

    public PreInvocationAuthorizationAdviceVoter(PreInvocationAuthorizationAdvice pre) {
        this.preAdvice = pre;
    }

    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof PreInvocationAuthorizationAdvice;
    }

    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(MethodInvocation.class);
    }

    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {

        // Find prefilter and preauth (or combined) attributes
        // if both null, abstain
        // else call advice with them

        PreInvocationAttribute preAttr = findPreInvocationAttribute(attributes);

        if (preAttr == null) {
            // No expression based metadata, so abstain
            return ACCESS_ABSTAIN;
        }

        boolean allowed = preAdvice.before(authentication, (MethodInvocation)object, preAttr);

        return allowed ? ACCESS_GRANTED : ACCESS_DENIED;
    }

    private PreInvocationAttribute findPreInvocationAttribute(Collection<ConfigAttribute> config) {
        for (ConfigAttribute attribute : config) {
            if (attribute instanceof PreInvocationAttribute) {
                return (PreInvocationAttribute)attribute;
            }
        }

        return null;
    }
}
