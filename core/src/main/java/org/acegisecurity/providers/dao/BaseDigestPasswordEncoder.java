/* Copyright 2004 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.sf.acegisecurity.providers.dao;

/**
 * <p>
 * Convenience base for Digest password encoders
 * </p>
 *
 * @author colin sampaleanu
 * @version $Id$
 */
public abstract class BaseDigestPasswordEncoder implements PasswordEncoder {
  
  //~ Instance fields ========================================================
  private boolean encodeHashAsBase64 = false;

  //~ Methods ================================================================
  
  /**
   * The encoded password is normally returned as Hex (32 char) version of the
   * hash bytes. Setting this property to true will cause the encoded pass to
   * be returned as Base64 text, which will consume 24 characters.
   */
  public void setEncodeHashAsBase64(boolean encodeHashAsBase64) {
    this.encodeHashAsBase64 = encodeHashAsBase64;
  }
  public boolean getEncodeHashAsBase64() {
    return encodeHashAsBase64;
  }

}
