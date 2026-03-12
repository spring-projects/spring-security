package org.springframework.security.kt.docs.servlet.oauth2.resourceserver.methodsecurityhasscope

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.stereotype.Service


@Service
open class MessageService {
    // tag::protected-method[]
    @PreAuthorize("@oauth2.hasScope('message:read')")
    open fun readMessage(): String {
        return "message"
    }
    // end::protected-method[]
}
