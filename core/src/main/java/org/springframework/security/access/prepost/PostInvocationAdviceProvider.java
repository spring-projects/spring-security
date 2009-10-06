package org.springframework.security.access.prepost;

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AfterInvocationProvider;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * <tt>AfterInvocationProvider</tt> which delegates to a {@link PostInvocationAuthorizationAdvice} instance
 * passing it the <tt>PostInvocationAttribute</tt> created from @PostAuthorize and @PostFilter annotations.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public class PostInvocationAdviceProvider implements AfterInvocationProvider {
    protected final Log logger = LogFactory.getLog(getClass());

    private PostInvocationAuthorizationAdvice postAdvice;

    public PostInvocationAdviceProvider(PostInvocationAuthorizationAdvice postAdvice) {
        this.postAdvice = postAdvice;
    }

    public Object decide(Authentication authentication, Object object, Collection<ConfigAttribute> config, Object returnedObject)
            throws AccessDeniedException {

        PostInvocationAttribute pia = findPostInvocationAttribute(config);

        if (pia == null) {
            return returnedObject;
        }

        return postAdvice.after(authentication, (MethodInvocation)object, pia, returnedObject);
    }

    private PostInvocationAttribute findPostInvocationAttribute(Collection<ConfigAttribute> config) {
        for (ConfigAttribute attribute : config) {
            if (attribute instanceof PostInvocationAttribute) {
                return (PostInvocationAttribute)attribute;
            }
        }

        return null;
    }

    public boolean supports(ConfigAttribute attribute) {
        return attribute instanceof PostInvocationAttribute;
    }

    public boolean supports(Class<?> clazz) {
        return clazz.isAssignableFrom(MethodInvocation.class);
    }
}
