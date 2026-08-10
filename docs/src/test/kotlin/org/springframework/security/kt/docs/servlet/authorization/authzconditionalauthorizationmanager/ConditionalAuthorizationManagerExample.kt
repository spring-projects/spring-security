package org.springframework.security.kt.docs.servlet.authorization.authzconditionalauthorizationmanager;

import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager
import org.springframework.security.authorization.ConditionalAuthorizationManager
import org.springframework.security.core.Authentication
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import java.util.function.Predicate

class ConditionalAuthorizationManagerExample {
    fun configure(mfaRepository: MfaRepository) {
        // tag::conditionalAuthorizationManager[]
        val whenUserHasMfa = Predicate { auth: Authentication -> mfaRepository.hasRegisteredMfa(auth.name) }
        val mfaRequired = AllRequiredFactorsAuthorizationManager.builder<RequestAuthorizationContext>()
            .requireFactor { f -> f.passwordAuthority() }
            .requireFactor { f -> f.webauthnAuthority() }
            .build()
        val manager = ConditionalAuthorizationManager.`when`<RequestAuthorizationContext>(whenUserHasMfa)
            .whenTrue(mfaRequired)
            .build()
        // end::conditionalAuthorizationManager[]
    }

    interface MfaRepository {
        fun hasRegisteredMfa(username: String?): Boolean
    }
}
