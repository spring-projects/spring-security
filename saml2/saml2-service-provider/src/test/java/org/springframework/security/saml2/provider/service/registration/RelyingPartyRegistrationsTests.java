/*
 * Copyright 2002-2020 the original author or authors.
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

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.Test;

import org.springframework.security.saml2.Saml2Exception;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatCode;

/**
 * Tests for {@link RelyingPartyRegistration}
 */
public class RelyingPartyRegistrationsTests {
	private static final String IDP_SSO_DESCRIPTOR_PAYLOAD =
			"<md:EntityDescriptor entityID=\"https://idp.example.com/idp/shibboleth\"\n" +
					"                     xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"\n" +
					"                     xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
					"                     xmlns:shibmd=\"urn:mace:shibboleth:metadata:1.0\"\n" +
					"                     xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"\n" +
					"                     xmlns:mdui=\"urn:oasis:names:tc:SAML:metadata:ui\">\n" +
					"    \n" +
					"   <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
					"      <md:Extensions>\n" +
					"         <shibmd:Scope regexp=\"false\">example.com</shibmd:Scope>\n" +
					"  \n" +
					"         <mdui:UIInfo>\n" +
					"            <mdui:DisplayName xml:lang=\"en\">\n" +
					"               Consortium GARR IdP\n" +
					"            </mdui:DisplayName>\n" +
					"            <mdui:DisplayName xml:lang=\"it\">\n" +
					"               Consortium GARR IdP\n" +
					"            </mdui:DisplayName>\n" +
					"    \n" +
					"            <mdui:Description xml:lang=\"en\">\n" +
					"               This Identity Provider gives support for the Consortium GARR's user community\n" +
					"            </mdui:Description>\n" +
					"            <mdui:Description xml:lang=\"it\">\n" +
					"               Questo Identity Provider di test fornisce supporto alla comunita' utenti GARR\n" +
					"            </mdui:Description>\n" +
					"         </mdui:UIInfo>\n" +
					"      </md:Extensions>\n" +
					"    \n" +
					"      <md:KeyDescriptor>\n" +
					"         <ds:KeyInfo>\n" +
					"            <ds:X509Data>\n" +
					"               <ds:X509Certificate>\n" +
					"                  MIIDZjCCAk6gAwIBAgIVAL9O+PA7SXtlwZZY8MVSE9On1cVWMA0GCSqGSIb3DQEB\n" +
					"                  BQUAMCkxJzAlBgNVBAMTHmlkZW0tcHVwYWdlbnQuZG16LWludC51bmltby5pdDAe\n" +
					"                  Fw0xMzA3MjQwMDQ0MTRaFw0zMzA3MjQwMDQ0MTRaMCkxJzAlBgNVBAMTHmlkZW0t\n" +
					"                  cHVwYWdlbnQuZG16LWludC51bmltby5pdDCCASIwDQYJKoZIhvcNAMIIDQADggEP\n" +
					"                  ADCCAQoCggEBAIAcp/VyzZGXUF99kwj4NvL/Rwv4YvBgLWzpCuoxqHZ/hmBwJtqS\n" +
					"                  v0y9METBPFbgsF3hCISnxbcmNVxf/D0MoeKtw1YPbsUmow/bFe+r72hZ+IVAcejN\n" +
					"                  iDJ7t5oTjsRN1t1SqvVVk6Ryk5AZhpFW+W9pE9N6c7kJ16Rp2/mbtax9OCzxpece\n" +
					"                  byi1eiLfIBmkcRawL/vCc2v6VLI18i6HsNVO3l2yGosKCbuSoGDx2fCdAOk/rgdz\n" +
					"                  cWOvFsIZSKuD+FVbSS/J9GVs7yotsS4PRl4iX9UMnfDnOMfO7bcBgbXtDl4SCU1v\n" +
					"                  dJrRw7IL/pLz34Rv9a8nYitrzrxtLOp3nYUCAwEAAaOBhDCBgTBgBgMIIDEEWTBX\n" +
					"                  gh5pZGVtLXB1cGFnZW50LmRtei1pbnQudW5pbW8uaXSGNWh0dHBzOi8vaWRlbS1w\n" +
					"                  dXBhZ2VudC5kbXotaW50LnVuaW1vLml0L2lkcC9zaGliYm9sZXRoMB0GA1UdDgQW\n" +
					"                  BBT8PANzz+adGnTRe8ldcyxAwe4VnzANBgkqhkiG9w0BAQUFAAOCAQEAOEnO8Clu\n" +
					"                  9z/Lf/8XOOsTdxJbV29DIF3G8KoQsB3dBsLwPZVEAQIP6ceS32Xaxrl6FMTDDNkL\n" +
					"                  qUvvInUisw0+I5zZwYHybJQCletUWTnz58SC4C9G7FpuXHFZnOGtRcgGD1NOX4UU\n" +
					"                  duus/4nVcGSLhDjszZ70Xtj0gw2Sn46oQPHTJ81QZ3Y9ih+Aj1c9OtUSBwtWZFkU\n" +
					"                  yooAKoR8li68Yb21zN2N65AqV+ndL98M8xUYMKLONuAXStDeoVCipH6PJ09Z5U2p\n" +
					"                  V5p4IQRV6QBsNw9CISJFuHzkVYTH5ZxzN80Ru46vh4y2M0Nu8GQ9I085KoZkrf5e\n" +
					"                  Cq53OZt9ISjHEw==\n" +
					"               </ds:X509Certificate>\n" +
					"            </ds:X509Data>\n" +
					"         </ds:KeyInfo>\n" +
					"      </md:KeyDescriptor>\n" +
					"   \n" +
					"      <md:SingleSignOnService\n" +
					"         Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
					"         Location=\"https://idp.example.com/idp/profile/SAML2/POST/SSO\"/>\n" +
					"   </md:IDPSSODescriptor>\n" +
					"    \n" +
					"   <md:Organization>\n" +
					"      <md:OrganizationName xml:lang=\"en\">\n" +
					"         Consortium GARR\n" +
					"      </md:OrganizationName>\n" +
					"      <md:OrganizationName xml:lang=\"it\">\n" +
					"         Consortium GARR\n" +
					"      </md:OrganizationName>\n" +
					"   \n" +
					"      <md:OrganizationDisplayName xml:lang=\"en\">\n" +
					"         Consortium GARR\n" +
					"      </md:OrganizationDisplayName>\n" +
					"      <md:OrganizationDisplayName xml:lang=\"it\">\n" +
					"         Consortium GARR\n" +
					"      </md:OrganizationDisplayName>\n" +
					"   \n" +
					"      <md:OrganizationURL xml:lang=\"it\">\n" +
					"         https://example.org\n" +
					"      </md:OrganizationURL>\n" +
					"   </md:Organization>\n" +
					"    \n" +
					"   <md:ContactPerson contactType=\"technical\">\n" +
					"      <md:EmailAddress>mailto:technical.contact@example.com</md:EmailAddress>\n" +
					"   </md:ContactPerson>\n" +
					"    \n" +
					"</md:EntityDescriptor>";

	@Test
	public void fromMetadataLocationWhenResolvableThenPopulatesBuilder() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.enqueue(new MockResponse().setBody(IDP_SSO_DESCRIPTOR_PAYLOAD).setResponseCode(200));
			RelyingPartyRegistration registration = RelyingPartyRegistrations
					.fromMetadataLocation(server.url("/").toString())
					.entityId("rp")
					.build();
			RelyingPartyRegistration.AssertingPartyDetails details = registration.getAssertingPartyDetails();
			assertThat(details.getEntityId()).isEqualTo("https://idp.example.com/idp/shibboleth");
			assertThat(details.getSingleSignOnServiceLocation())
					.isEqualTo("https://idp.example.com/idp/profile/SAML2/POST/SSO");
			assertThat(details.getSingleSignOnServiceBinding())
					.isEqualTo(Saml2MessageBinding.POST);
			assertThat(details.getVerificationX509Credentials()).hasSize(1);
			assertThat(details.getEncryptionX509Credentials()).hasSize(1);
		}
	}

	@Test
	public void fromMetadataLocationWhenUnresolvableThenSaml2Exception() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.enqueue(new MockResponse().setBody(IDP_SSO_DESCRIPTOR_PAYLOAD).setResponseCode(200));
			String url = server.url("/").toString();
			server.shutdown();
			assertThatCode(() -> RelyingPartyRegistrations.fromMetadataLocation(url))
					.isInstanceOf(Saml2Exception.class);
		}
	}

	@Test
	public void fromMetadataLocationWhenMalformedResponseThenSaml2Exception() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.enqueue(new MockResponse().setBody("malformed").setResponseCode(200));
			String url = server.url("/").toString();
			assertThatCode(() -> RelyingPartyRegistrations.fromMetadataLocation(url))
					.isInstanceOf(Saml2Exception.class);
		}
	}
}
