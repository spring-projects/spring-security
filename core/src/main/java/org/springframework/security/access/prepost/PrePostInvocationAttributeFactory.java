package org.springframework.security.access.prepost;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0
 */
public interface PrePostInvocationAttributeFactory {

    PreInvocationAttribute createPreInvocationAttribute(PreFilter preFilter, PreAuthorize preAuthorize);

    PostInvocationAttribute createPostInvocationAttribute(PostFilter postFilter, PostAuthorize postAuthorize);
}
