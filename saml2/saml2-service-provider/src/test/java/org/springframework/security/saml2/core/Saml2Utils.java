/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.saml2.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import org.apache.commons.codec.binary.Base64;

import org.springframework.security.saml2.Saml2Exception;

public final class Saml2Utils {

	public static final String INVALID_BASE64 = "cmVzcG9 \n\t\r uc2U9+/";

	private static Base64 BASE64 = new Base64(0, new byte[] { '\n' });

	private Saml2Utils() {
	}

	public static String samlEncode(byte[] b) {
		return BASE64.encodeAsString(b);
	}

	public static byte[] samlDecode(String s) {
		return BASE64.decode(s);
	}

	public static byte[] samlDeflate(String s) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(out,
					new Deflater(Deflater.DEFLATED, true));
			deflaterOutputStream.write(s.getBytes(StandardCharsets.UTF_8));
			deflaterOutputStream.finish();
			return out.toByteArray();
		}
		catch (IOException ex) {
			throw new Saml2Exception("Unable to deflate string", ex);
		}
	}

	public static String samlInflate(byte[] b) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			InflaterOutputStream inflaterOutputStream = new InflaterOutputStream(out, new Inflater(true));
			inflaterOutputStream.write(b);
			inflaterOutputStream.finish();
			return new String(out.toByteArray(), StandardCharsets.UTF_8);
		}
		catch (IOException ex) {
			throw new Saml2Exception("Unable to inflate string", ex);
		}
	}

	public static byte[] invalidSamlDeflate(String s) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(out,
					new Deflater(Deflater.DEFLATED, false));
			deflaterOutputStream.write(s.getBytes(StandardCharsets.UTF_8));
			deflaterOutputStream.finish();
			return out.toByteArray();
		}
		catch (IOException ex) {
			throw new Saml2Exception("Unable to deflate string", ex);
		}
	}

}
