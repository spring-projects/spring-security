/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.saml2.provider.service.registration;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.saml2.core.OpenSamlInitializationService;

/**
 * An {@link HttpMessageConverter} that takes an {@code IDPSSODescriptor} in an HTTP
 * response and converts it into a {@link RelyingPartyRegistration.Builder}.
 *
 * The primary use case for this is constructing a {@link RelyingPartyRegistration} for
 * inclusion in a {@link RelyingPartyRegistrationRepository}. To do so, you can include an
 * instance of this converter in a {@link org.springframework.web.client.RestOperations}
 * like so:
 *
 * <pre>
 * 		RestOperations rest = new RestTemplate(Collections.singletonList(
 *     			new RelyingPartyRegistrationsBuilderHttpMessageConverter()));
 * 		RelyingPartyRegistration.Builder builder = rest.getForObject
 * 				("https://idp.example.org/metadata", RelyingPartyRegistration.Builder.class);
 * 		RelyingPartyRegistration registration = builder.registrationId("registration-id").build();
 * </pre>
 *
 * Note that this will only configure the asserting party (IDP) half of the
 * {@link RelyingPartyRegistration}, meaning where and how to send AuthnRequests, how to
 * verify Assertions, etc.
 *
 * To further configure the {@link RelyingPartyRegistration} with relying party (SP)
 * information, you may invoke the appropriate methods on the builder.
 *
 * @author Josh Cummings
 * @since 5.4
 */
public class OpenSamlRelyingPartyRegistrationBuilderHttpMessageConverter
		implements HttpMessageConverter<RelyingPartyRegistration.Builder> {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final OpenSamlMetadataAssertingPartyDetailsConverter converter;

	/**
	 * Creates a {@link OpenSamlRelyingPartyRegistrationBuilderHttpMessageConverter}
	 */
	public OpenSamlRelyingPartyRegistrationBuilderHttpMessageConverter() {
		this.converter = new OpenSamlMetadataAssertingPartyDetailsConverter();
	}

	@Override
	public boolean canRead(Class<?> clazz, MediaType mediaType) {
		return RelyingPartyRegistration.Builder.class.isAssignableFrom(clazz);
	}

	@Override
	public boolean canWrite(Class<?> clazz, MediaType mediaType) {
		return false;
	}

	@Override
	public List<MediaType> getSupportedMediaTypes() {
		return Arrays.asList(MediaType.APPLICATION_XML, MediaType.TEXT_XML);
	}

	@Override
	public RelyingPartyRegistration.Builder read(Class<? extends RelyingPartyRegistration.Builder> clazz,
			HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
		return RelyingPartyRegistration
				.withAssertingPartyDetails(this.converter.convert(inputMessage.getBody()).iterator().next().build());
	}

	@Override
	public void write(RelyingPartyRegistration.Builder builder, MediaType contentType, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		throw new HttpMessageNotWritableException("This converter cannot write a RelyingPartyRegistration.Builder");
	}

}
