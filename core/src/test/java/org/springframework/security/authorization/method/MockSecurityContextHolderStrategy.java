package org.springframework.security.authorization.method;

import org.springframework.security.core.context.*;

import static org.mockito.BDDMockito.*;
import static org.mockito.Mockito.*;

public class MockSecurityContextHolderStrategy {
	static SecurityContextHolderStrategy getmock(SecurityContextImpl securityContextImpl){

		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getContext()).willReturn(securityContextImpl);
		return strategy;
	}
}
