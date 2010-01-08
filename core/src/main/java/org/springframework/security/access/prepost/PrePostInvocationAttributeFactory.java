package org.springframework.security.access.prepost;

import org.springframework.aop.framework.AopInfrastructureBean;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface PrePostInvocationAttributeFactory extends AopInfrastructureBean {

    PreInvocationAttribute createPreInvocationAttribute(PreFilter preFilter, PreAuthorize preAuthorize);

    PostInvocationAttribute createPostInvocationAttribute(PostFilter postFilter, PostAuthorize postAuthorize);
}
