package org.springframework.security.access.prepost;

import org.springframework.aop.framework.AopInfrastructureBean;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface PrePostInvocationAttributeFactory extends AopInfrastructureBean {

    PreInvocationAttribute createPreInvocationAttribute(String preFilterAttribute, String filterObject, String preAuthorizeAttribute);

    PostInvocationAttribute createPostInvocationAttribute(String postFilterAttribute, String postAuthorizeAttribute);
}
