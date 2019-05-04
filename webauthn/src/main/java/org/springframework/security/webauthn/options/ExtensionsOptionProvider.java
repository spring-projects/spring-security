/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.webauthn.options;

import com.webauthn4j.data.extension.ExtensionInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.ExtensionClientInput;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class ExtensionsOptionProvider<T extends ExtensionClientInput> implements Iterable<ExtensionOptionProvider<T>> {

	private Map<String, ExtensionOptionProvider<T>> providers = new HashMap<>();

	public AuthenticationExtensionsClientInputs<T> provide(HttpServletRequest request) {

		Map<String, T> extensionOptions =
				providers.values().stream()
						.map(provider -> provider.provide(request))
						.collect(Collectors.toMap(ExtensionInput::getIdentifier, extensionOption -> extensionOption));

		return new AuthenticationExtensionsClientInputs<>(extensionOptions);
	}

	public void put(T extensionOption) {
		put(new StaticExtensionOptionProvider<>(extensionOption));
	}

	public void put(ExtensionOptionProvider<T> extensionOptionProvider) {
		providers.put(extensionOptionProvider.getIdentifier(), extensionOptionProvider);
	}

	public void putAll(Map<String, ExtensionOptionProvider<T>> extensionsClientInputs) {
		extensionsClientInputs.forEach((key, value) -> providers.put(key, value));
	}

	@Override
	public Iterator<ExtensionOptionProvider<T>> iterator() {
		return providers.values().iterator();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		ExtensionsOptionProvider<?> that = (ExtensionsOptionProvider<?>) o;
		return Objects.equals(providers, that.providers);
	}

	@Override
	public int hashCode() {
		return Objects.hash(providers);
	}
}
