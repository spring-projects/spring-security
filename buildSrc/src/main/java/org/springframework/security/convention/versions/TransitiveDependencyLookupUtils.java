/*
 * Copyright 2019-2020 the original author or authors.
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

package org.springframework.security.convention.versions;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.InputStream;

class TransitiveDependencyLookupUtils {
	static String OIDC_SDK_NAME = "oauth2-oidc-sdk";
	static String NIMBUS_JOSE_JWT_NAME = "nimbus-jose-jwt";

	private static OkHttpClient client = new OkHttpClient();

	static String lookupJwtVersion(String oauthSdcVersion) {
		Request request = new Request.Builder()
				.get()
				.url("https://repo.maven.apache.org/maven2/com/nimbusds/" + OIDC_SDK_NAME + "/" + oauthSdcVersion + "/" + OIDC_SDK_NAME + "-" + oauthSdcVersion + ".pom")
				.build();
		try (Response response = client.newCall(request).execute()) {
			if (!response.isSuccessful()) {
				throw new IOException("Unexpected code " + response);
			}
			InputStream inputStream = response.body().byteStream();
			return getVersion(inputStream);

		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	private static String getVersion(InputStream inputStream) throws ParserConfigurationException, IOException, SAXException, XPathExpressionException {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		DocumentBuilder db = dbf.newDocumentBuilder();

		Document doc = db.parse(inputStream);

		doc.getDocumentElement().normalize();

		XPath xPath = XPathFactory.newInstance().newXPath();
		return xPath.evaluate("/project/dependencies/dependency/version[../artifactId/text() = \"" + NIMBUS_JOSE_JWT_NAME + "\"]", doc);
	}
}
