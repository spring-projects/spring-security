package org.springframework.security.authorization.method;

import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;

import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * Tests for {@link AuthorizationAnnotationUtils}
 */
class AuthorizationAnnotationUtilsTests {

	@Test // gh-13132
	public void annotationsOnSyntheticMethodsShouldNotTriggerAnnotationConfigurationException()
			throws NoSuchMethodException {
		StringRepository proxy =
				(StringRepository) Proxy.newProxyInstance(Thread.currentThread().getContextClassLoader(),
						new Class[] {StringRepository.class}, (p, m, args) -> null);
		Method method = proxy.getClass().getDeclaredMethod("findAll");
		assertThatNoException()
				.isThrownBy(() -> AuthorizationAnnotationUtils.findUniqueAnnotation(method, PreAuthorize.class));
	}

	private interface BaseRepository<T> {

		Iterable<T> findAll();
	}

	private interface StringRepository extends BaseRepository<String> {

		@Override
		@PreAuthorize("hasRole('someRole')")
		List<String> findAll();
	}
}
