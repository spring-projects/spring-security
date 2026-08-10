package org.springframework.security.docs.servlet.authorization.authzconditionalauthorizationmanager;

import java.util.function.Predicate;

import org.springframework.security.authorization.AllRequiredFactorsAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ConditionalAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

public class ConditionalAuthorizationManagerExample {

	public void configure(MfaRepository mfaRepository) {
		// tag::conditionalAuthorizationManager[]
		Predicate<Authentication> whenUserHasMfa = (auth) -> mfaRepository.hasRegisteredMfa(auth.getName());
		AuthorizationManager<RequestAuthorizationContext> mfaRequired = AllRequiredFactorsAuthorizationManager
			.<RequestAuthorizationContext>builder()
			.requireFactor((f) -> f.passwordAuthority())
			.requireFactor((f) -> f.webauthnAuthority())
			.build();
		AuthorizationManager<RequestAuthorizationContext> manager = ConditionalAuthorizationManager.<RequestAuthorizationContext>when(whenUserHasMfa)
			.whenTrue(mfaRequired)
			.build();
		// end::conditionalAuthorizationManager[]
	}

	interface MfaRepository {

		boolean hasRegisteredMfa(String username);

	}

}
