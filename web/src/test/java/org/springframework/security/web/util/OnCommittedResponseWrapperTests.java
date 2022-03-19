/*
 * Copyright 2002-2015 the original author or authors.
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

package org.springframework.security.web.util;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class OnCommittedResponseWrapperTests {

	private static final String NL = "\r\n";

	@Mock
	HttpServletResponse delegate;

	@Mock
	PrintWriter writer;

	@Mock
	ServletOutputStream out;

	OnCommittedResponseWrapper response;

	boolean committed;

	@BeforeEach
	public void setup() throws Exception {
		this.response = new OnCommittedResponseWrapper(this.delegate) {
			@Override
			protected void onResponseCommitted() {
				OnCommittedResponseWrapperTests.this.committed = true;
			}
		};
	}

	private void givenGetWriterThenReturn() throws IOException {
		given(this.delegate.getWriter()).willReturn(this.writer);
	}

	private void givenGetOutputStreamThenReturn() throws IOException {
		given(this.delegate.getOutputStream()).willReturn(this.out);
	}

	@Test
	public void printWriterHashCode() throws Exception {
		givenGetWriterThenReturn();
		int expected = this.writer.hashCode();
		assertThat(this.response.getWriter().hashCode()).isEqualTo(expected);
	}

	@Test
	public void printWriterCheckError() throws Exception {
		givenGetWriterThenReturn();
		boolean expected = true;
		given(this.writer.checkError()).willReturn(expected);
		assertThat(this.response.getWriter().checkError()).isEqualTo(expected);
	}

	@Test
	public void printWriterWriteInt() throws Exception {
		givenGetWriterThenReturn();
		int expected = 1;
		this.response.getWriter().write(expected);
		verify(this.writer).write(expected);
	}

	@Test
	public void printWriterWriteCharIntInt() throws Exception {
		givenGetWriterThenReturn();
		char[] buff = new char[0];
		int off = 2;
		int len = 3;
		this.response.getWriter().write(buff, off, len);
		verify(this.writer).write(buff, off, len);
	}

	@Test
	public void printWriterWriteChar() throws Exception {
		givenGetWriterThenReturn();
		char[] buff = new char[0];
		this.response.getWriter().write(buff);
		verify(this.writer).write(buff);
	}

	@Test
	public void printWriterWriteStringIntInt() throws Exception {
		givenGetWriterThenReturn();
		String s = "";
		int off = 2;
		int len = 3;
		this.response.getWriter().write(s, off, len);
		verify(this.writer).write(s, off, len);
	}

	@Test
	public void printWriterWriteString() throws Exception {
		givenGetWriterThenReturn();
		String s = "";
		this.response.getWriter().write(s);
		verify(this.writer).write(s);
	}

	@Test
	public void printWriterPrintBoolean() throws Exception {
		givenGetWriterThenReturn();
		boolean b = true;
		this.response.getWriter().print(b);
		verify(this.writer).print(b);
	}

	@Test
	public void printWriterPrintChar() throws Exception {
		givenGetWriterThenReturn();
		char c = 1;
		this.response.getWriter().print(c);
		verify(this.writer).print(c);
	}

	@Test
	public void printWriterPrintInt() throws Exception {
		givenGetWriterThenReturn();
		int i = 1;
		this.response.getWriter().print(i);
		verify(this.writer).print(i);
	}

	@Test
	public void printWriterPrintLong() throws Exception {
		givenGetWriterThenReturn();
		long l = 1;
		this.response.getWriter().print(l);
		verify(this.writer).print(l);
	}

	@Test
	public void printWriterPrintFloat() throws Exception {
		givenGetWriterThenReturn();
		float f = 1;
		this.response.getWriter().print(f);
		verify(this.writer).print(f);
	}

	@Test
	public void printWriterPrintDouble() throws Exception {
		givenGetWriterThenReturn();
		double x = 1;
		this.response.getWriter().print(x);
		verify(this.writer).print(x);
	}

	@Test
	public void printWriterPrintCharArray() throws Exception {
		givenGetWriterThenReturn();
		char[] x = new char[0];
		this.response.getWriter().print(x);
		verify(this.writer).print(x);
	}

	@Test
	public void printWriterPrintString() throws Exception {
		givenGetWriterThenReturn();
		String x = "1";
		this.response.getWriter().print(x);
		verify(this.writer).print(x);
	}

	@Test
	public void printWriterPrintObject() throws Exception {
		givenGetWriterThenReturn();
		Object x = "1";
		this.response.getWriter().print(x);
		verify(this.writer).print(x);
	}

	@Test
	public void printWriterPrintln() throws Exception {
		givenGetWriterThenReturn();
		this.response.getWriter().println();
		verify(this.writer).println();
	}

	@Test
	public void printWriterPrintlnBoolean() throws Exception {
		givenGetWriterThenReturn();
		boolean b = true;
		this.response.getWriter().println(b);
		verify(this.writer).println(b);
	}

	@Test
	public void printWriterPrintlnChar() throws Exception {
		givenGetWriterThenReturn();
		char c = 1;
		this.response.getWriter().println(c);
		verify(this.writer).println(c);
	}

	@Test
	public void printWriterPrintlnInt() throws Exception {
		givenGetWriterThenReturn();
		int i = 1;
		this.response.getWriter().println(i);
		verify(this.writer).println(i);
	}

	@Test
	public void printWriterPrintlnLong() throws Exception {
		givenGetWriterThenReturn();
		long l = 1;
		this.response.getWriter().println(l);
		verify(this.writer).println(l);
	}

	@Test
	public void printWriterPrintlnFloat() throws Exception {
		givenGetWriterThenReturn();
		float f = 1;
		this.response.getWriter().println(f);
		verify(this.writer).println(f);
	}

	@Test
	public void printWriterPrintlnDouble() throws Exception {
		givenGetWriterThenReturn();
		double x = 1;
		this.response.getWriter().println(x);
		verify(this.writer).println(x);
	}

	@Test
	public void printWriterPrintlnCharArray() throws Exception {
		givenGetWriterThenReturn();
		char[] x = new char[0];
		this.response.getWriter().println(x);
		verify(this.writer).println(x);
	}

	@Test
	public void printWriterPrintlnString() throws Exception {
		givenGetWriterThenReturn();
		String x = "1";
		this.response.getWriter().println(x);
		verify(this.writer).println(x);
	}

	@Test
	public void printWriterPrintlnObject() throws Exception {
		givenGetWriterThenReturn();
		Object x = "1";
		this.response.getWriter().println(x);
		verify(this.writer).println(x);
	}

	@Test
	public void printWriterPrintfStringObjectVargs() throws Exception {
		givenGetWriterThenReturn();
		String format = "format";
		Object[] args = new Object[] { "1" };
		this.response.getWriter().printf(format, args);
		verify(this.writer).printf(format, args);
	}

	@Test
	public void printWriterPrintfLocaleStringObjectVargs() throws Exception {
		givenGetWriterThenReturn();
		Locale l = Locale.US;
		String format = "format";
		Object[] args = new Object[] { "1" };
		this.response.getWriter().printf(l, format, args);
		verify(this.writer).printf(l, format, args);
	}

	@Test
	public void printWriterFormatStringObjectVargs() throws Exception {
		givenGetWriterThenReturn();
		String format = "format";
		Object[] args = new Object[] { "1" };
		this.response.getWriter().format(format, args);
		verify(this.writer).format(format, args);
	}

	@Test
	public void printWriterFormatLocaleStringObjectVargs() throws Exception {
		givenGetWriterThenReturn();
		Locale l = Locale.US;
		String format = "format";
		Object[] args = new Object[] { "1" };
		this.response.getWriter().format(l, format, args);
		verify(this.writer).format(l, format, args);
	}

	@Test
	public void printWriterAppendCharSequence() throws Exception {
		givenGetWriterThenReturn();
		String x = "a";
		this.response.getWriter().append(x);
		verify(this.writer).append(x);
	}

	@Test
	public void printWriterAppendCharSequenceIntInt() throws Exception {
		givenGetWriterThenReturn();
		String x = "abcdef";
		int start = 1;
		int end = 3;
		this.response.getWriter().append(x, start, end);
		verify(this.writer).append(x, start, end);
	}

	@Test
	public void printWriterAppendChar() throws Exception {
		givenGetWriterThenReturn();
		char x = 1;
		this.response.getWriter().append(x);
		verify(this.writer).append(x);
	}

	// servletoutputstream
	@Test
	public void outputStreamHashCode() throws Exception {
		givenGetOutputStreamThenReturn();
		int expected = this.out.hashCode();
		assertThat(this.response.getOutputStream().hashCode()).isEqualTo(expected);
	}

	@Test
	public void outputStreamWriteInt() throws Exception {
		givenGetOutputStreamThenReturn();
		int expected = 1;
		this.response.getOutputStream().write(expected);
		verify(this.out).write(expected);
	}

	@Test
	public void outputStreamWriteByte() throws Exception {
		givenGetOutputStreamThenReturn();
		byte[] expected = new byte[0];
		this.response.getOutputStream().write(expected);
		verify(this.out).write(expected);
	}

	@Test
	public void outputStreamWriteByteIntInt() throws Exception {
		givenGetOutputStreamThenReturn();
		int start = 1;
		int end = 2;
		byte[] expected = new byte[0];
		this.response.getOutputStream().write(expected, start, end);
		verify(this.out).write(expected, start, end);
	}

	@Test
	public void outputStreamPrintBoolean() throws Exception {
		givenGetOutputStreamThenReturn();
		boolean b = true;
		this.response.getOutputStream().print(b);
		verify(this.out).print(b);
	}

	@Test
	public void outputStreamPrintChar() throws Exception {
		givenGetOutputStreamThenReturn();
		char c = 1;
		this.response.getOutputStream().print(c);
		verify(this.out).print(c);
	}

	@Test
	public void outputStreamPrintInt() throws Exception {
		givenGetOutputStreamThenReturn();
		int i = 1;
		this.response.getOutputStream().print(i);
		verify(this.out).print(i);
	}

	@Test
	public void outputStreamPrintLong() throws Exception {
		givenGetOutputStreamThenReturn();
		long l = 1;
		this.response.getOutputStream().print(l);
		verify(this.out).print(l);
	}

	@Test
	public void outputStreamPrintFloat() throws Exception {
		givenGetOutputStreamThenReturn();
		float f = 1;
		this.response.getOutputStream().print(f);
		verify(this.out).print(f);
	}

	@Test
	public void outputStreamPrintDouble() throws Exception {
		givenGetOutputStreamThenReturn();
		double x = 1;
		this.response.getOutputStream().print(x);
		verify(this.out).print(x);
	}

	@Test
	public void outputStreamPrintString() throws Exception {
		givenGetOutputStreamThenReturn();
		String x = "1";
		this.response.getOutputStream().print(x);
		verify(this.out).print(x);
	}

	@Test
	public void outputStreamPrintln() throws Exception {
		givenGetOutputStreamThenReturn();
		this.response.getOutputStream().println();
		verify(this.out).println();
	}

	@Test
	public void outputStreamPrintlnBoolean() throws Exception {
		givenGetOutputStreamThenReturn();
		boolean b = true;
		this.response.getOutputStream().println(b);
		verify(this.out).println(b);
	}

	@Test
	public void outputStreamPrintlnChar() throws Exception {
		givenGetOutputStreamThenReturn();
		char c = 1;
		this.response.getOutputStream().println(c);
		verify(this.out).println(c);
	}

	@Test
	public void outputStreamPrintlnInt() throws Exception {
		givenGetOutputStreamThenReturn();
		int i = 1;
		this.response.getOutputStream().println(i);
		verify(this.out).println(i);
	}

	@Test
	public void outputStreamPrintlnLong() throws Exception {
		givenGetOutputStreamThenReturn();
		long l = 1;
		this.response.getOutputStream().println(l);
		verify(this.out).println(l);
	}

	@Test
	public void outputStreamPrintlnFloat() throws Exception {
		givenGetOutputStreamThenReturn();
		float f = 1;
		this.response.getOutputStream().println(f);
		verify(this.out).println(f);
	}

	@Test
	public void outputStreamPrintlnDouble() throws Exception {
		givenGetOutputStreamThenReturn();
		double x = 1;
		this.response.getOutputStream().println(x);
		verify(this.out).println(x);
	}

	@Test
	public void outputStreamPrintlnString() throws Exception {
		givenGetOutputStreamThenReturn();
		String x = "1";
		this.response.getOutputStream().println(x);
		verify(this.out).println(x);
	}

	// The amount of content specified in the setContentLength method of the response
	// has been greater than zero and has been written to the response.
	// gh-3823
	@Test
	public void contentLengthPrintWriterWriteNullCommits() throws Exception {
		givenGetWriterThenReturn();
		String expected = null;
		this.response.setContentLength(String.valueOf(expected).length() + 1);
		this.response.getWriter().write(expected);
		assertThat(this.committed).isFalse();
		this.response.getWriter().write("a");
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterWriteIntCommits() throws Exception {
		givenGetWriterThenReturn();
		int expected = 1;
		this.response.setContentLength(String.valueOf(expected).length());
		this.response.getWriter().write(expected);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterWriteIntMultiDigitCommits() throws Exception {
		givenGetWriterThenReturn();
		int expected = 10000;
		this.response.setContentLength(String.valueOf(expected).length());
		this.response.getWriter().write(expected);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPlus1PrintWriterWriteIntMultiDigitCommits() throws Exception {
		givenGetWriterThenReturn();
		int expected = 10000;
		this.response.setContentLength(String.valueOf(expected).length() + 1);
		this.response.getWriter().write(expected);
		assertThat(this.committed).isFalse();
		this.response.getWriter().write(1);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterWriteCharIntIntCommits() throws Exception {
		givenGetWriterThenReturn();
		char[] buff = new char[0];
		int off = 2;
		int len = 3;
		this.response.setContentLength(3);
		this.response.getWriter().write(buff, off, len);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterWriteCharCommits() throws Exception {
		givenGetWriterThenReturn();
		char[] buff = new char[4];
		this.response.setContentLength(buff.length);
		this.response.getWriter().write(buff);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterWriteStringIntIntCommits() throws Exception {
		givenGetWriterThenReturn();
		String s = "";
		int off = 2;
		int len = 3;
		this.response.setContentLength(3);
		this.response.getWriter().write(s, off, len);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterWriteStringCommits() throws IOException {
		givenGetWriterThenReturn();
		String body = "something";
		this.response.setContentLength(body.length());
		this.response.getWriter().write(body);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void printWriterWriteStringContentLengthCommits() throws IOException {
		givenGetWriterThenReturn();
		String body = "something";
		this.response.getWriter().write(body);
		this.response.setContentLength(body.length());
		assertThat(this.committed).isTrue();
	}

	@Test
	public void printWriterWriteStringDoesNotCommit() throws IOException {
		givenGetWriterThenReturn();
		String body = "something";
		this.response.getWriter().write(body);
		assertThat(this.committed).isFalse();
	}

	@Test
	public void contentLengthPrintWriterPrintBooleanCommits() throws Exception {
		givenGetWriterThenReturn();
		boolean b = true;
		this.response.setContentLength(1);
		this.response.getWriter().print(b);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintCharCommits() throws Exception {
		givenGetWriterThenReturn();
		char c = 1;
		this.response.setContentLength(1);
		this.response.getWriter().print(c);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintIntCommits() throws Exception {
		givenGetWriterThenReturn();
		int i = 1234;
		this.response.setContentLength(String.valueOf(i).length());
		this.response.getWriter().print(i);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintLongCommits() throws Exception {
		givenGetWriterThenReturn();
		long l = 12345;
		this.response.setContentLength(String.valueOf(l).length());
		this.response.getWriter().print(l);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintFloatCommits() throws Exception {
		givenGetWriterThenReturn();
		float f = 12345;
		this.response.setContentLength(String.valueOf(f).length());
		this.response.getWriter().print(f);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintDoubleCommits() throws Exception {
		givenGetWriterThenReturn();
		double x = 1.2345;
		this.response.setContentLength(String.valueOf(x).length());
		this.response.getWriter().print(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintCharArrayCommits() throws Exception {
		givenGetWriterThenReturn();
		char[] x = new char[10];
		this.response.setContentLength(x.length);
		this.response.getWriter().print(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintStringCommits() throws Exception {
		givenGetWriterThenReturn();
		String x = "12345";
		this.response.setContentLength(x.length());
		this.response.getWriter().print(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintObjectCommits() throws Exception {
		givenGetWriterThenReturn();
		Object x = "12345";
		this.response.setContentLength(String.valueOf(x).length());
		this.response.getWriter().print(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnCommits() throws Exception {
		givenGetWriterThenReturn();
		this.response.setContentLength(NL.length());
		this.response.getWriter().println();
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnBooleanCommits() throws Exception {
		givenGetWriterThenReturn();
		boolean b = true;
		this.response.setContentLength(1);
		this.response.getWriter().println(b);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnCharCommits() throws Exception {
		givenGetWriterThenReturn();
		char c = 1;
		this.response.setContentLength(1);
		this.response.getWriter().println(c);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnIntCommits() throws Exception {
		givenGetWriterThenReturn();
		int i = 12345;
		this.response.setContentLength(String.valueOf(i).length());
		this.response.getWriter().println(i);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnLongCommits() throws Exception {
		givenGetWriterThenReturn();
		long l = 12345678;
		this.response.setContentLength(String.valueOf(l).length());
		this.response.getWriter().println(l);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnFloatCommits() throws Exception {
		givenGetWriterThenReturn();
		float f = 1234;
		this.response.setContentLength(String.valueOf(f).length());
		this.response.getWriter().println(f);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnDoubleCommits() throws Exception {
		givenGetWriterThenReturn();
		double x = 1;
		this.response.setContentLength(String.valueOf(x).length());
		this.response.getWriter().println(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnCharArrayCommits() throws Exception {
		givenGetWriterThenReturn();
		char[] x = new char[20];
		this.response.setContentLength(x.length);
		this.response.getWriter().println(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnStringCommits() throws Exception {
		givenGetWriterThenReturn();
		String x = "1";
		this.response.setContentLength(String.valueOf(x).length());
		this.response.getWriter().println(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnObjectCommits() throws Exception {
		givenGetWriterThenReturn();
		Object x = "1";
		this.response.setContentLength(String.valueOf(x).length());
		this.response.getWriter().println(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterAppendCharSequenceCommits() throws Exception {
		givenGetWriterThenReturn();
		String x = "a";
		this.response.setContentLength(String.valueOf(x).length());
		this.response.getWriter().append(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterAppendCharSequenceIntIntCommits() throws Exception {
		givenGetWriterThenReturn();
		String x = "abcdef";
		int start = 1;
		int end = 3;
		this.response.setContentLength(end - start);
		this.response.getWriter().append(x, start, end);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterAppendCharCommits() throws Exception {
		givenGetWriterThenReturn();
		char x = 1;
		this.response.setContentLength(1);
		this.response.getWriter().append(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamWriteIntCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		int expected = 1;
		this.response.setContentLength(String.valueOf(expected).length());
		this.response.getOutputStream().write(expected);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamWriteIntMultiDigitCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		int expected = 10000;
		this.response.setContentLength(String.valueOf(expected).length());
		this.response.getOutputStream().write(expected);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPlus1OutputStreamWriteIntMultiDigitCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		int expected = 10000;
		this.response.setContentLength(String.valueOf(expected).length() + 1);
		this.response.getOutputStream().write(expected);
		assertThat(this.committed).isFalse();
		this.response.getOutputStream().write(1);
		assertThat(this.committed).isTrue();
	}

	// gh-171
	@Test
	public void contentLengthPlus1OutputStreamWriteByteArrayMultiDigitCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		String expected = "{\n" + "  \"parameterName\" : \"_csrf\",\n"
				+ "  \"token\" : \"06300b65-c4aa-4c8f-8cda-39ee17f545a0\",\n" + "  \"headerName\" : \"X-CSRF-TOKEN\"\n"
				+ "}";
		this.response.setContentLength(expected.length() + 1);
		this.response.getOutputStream().write(expected.getBytes());
		assertThat(this.committed).isFalse();
		this.response.getOutputStream().write("1".getBytes("UTF-8"));
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintBooleanCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		boolean b = true;
		this.response.setContentLength(1);
		this.response.getOutputStream().print(b);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintCharCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		char c = 1;
		this.response.setContentLength(1);
		this.response.getOutputStream().print(c);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintIntCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		int i = 1234;
		this.response.setContentLength(String.valueOf(i).length());
		this.response.getOutputStream().print(i);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintLongCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		long l = 12345;
		this.response.setContentLength(String.valueOf(l).length());
		this.response.getOutputStream().print(l);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintFloatCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		float f = 12345;
		this.response.setContentLength(String.valueOf(f).length());
		this.response.getOutputStream().print(f);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintDoubleCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		double x = 1.2345;
		this.response.setContentLength(String.valueOf(x).length());
		this.response.getOutputStream().print(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintStringCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		String x = "12345";
		this.response.setContentLength(x.length());
		this.response.getOutputStream().print(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		this.response.setContentLength(NL.length());
		this.response.getOutputStream().println();
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnBooleanCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		boolean b = true;
		this.response.setContentLength(1);
		this.response.getOutputStream().println(b);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnCharCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		char c = 1;
		this.response.setContentLength(1);
		this.response.getOutputStream().println(c);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnIntCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		int i = 12345;
		this.response.setContentLength(String.valueOf(i).length());
		this.response.getOutputStream().println(i);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnLongCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		long l = 12345678;
		this.response.setContentLength(String.valueOf(l).length());
		this.response.getOutputStream().println(l);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnFloatCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		float f = 1234;
		this.response.setContentLength(String.valueOf(f).length());
		this.response.getOutputStream().println(f);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnDoubleCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		double x = 1;
		this.response.setContentLength(String.valueOf(x).length());
		this.response.getOutputStream().println(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnStringCommits() throws Exception {
		givenGetOutputStreamThenReturn();
		String x = "1";
		this.response.setContentLength(String.valueOf(x).length());
		this.response.getOutputStream().println(x);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthDoesNotCommit() {
		String body = "something";
		this.response.setContentLength(body.length());
		assertThat(this.committed).isFalse();
	}

	@Test
	public void contentLengthOutputStreamWriteStringCommits() throws IOException {
		givenGetOutputStreamThenReturn();
		String body = "something";
		this.response.setContentLength(body.length());
		this.response.getOutputStream().print(body);
		assertThat(this.committed).isTrue();
	}

	// gh-7261
	@Test
	public void contentLengthLongOutputStreamWriteStringCommits() throws IOException {
		givenGetOutputStreamThenReturn();
		String body = "something";
		this.response.setContentLengthLong(body.length());
		this.response.getOutputStream().print(body);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void addHeaderContentLengthPrintWriterWriteStringCommits() throws Exception {
		givenGetWriterThenReturn();
		int expected = 1234;
		this.response.addHeader("Content-Length", String.valueOf(String.valueOf(expected).length()));
		this.response.getWriter().write(expected);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void bufferSizePrintWriterWriteCommits() throws Exception {
		givenGetWriterThenReturn();
		String expected = "1234567890";
		given(this.response.getBufferSize()).willReturn(expected.length());
		this.response.getWriter().write(expected);
		assertThat(this.committed).isTrue();
	}

	@Test
	public void bufferSizeCommitsOnce() throws Exception {
		givenGetWriterThenReturn();
		String expected = "1234567890";
		given(this.response.getBufferSize()).willReturn(expected.length());
		this.response.getWriter().write(expected);
		assertThat(this.committed).isTrue();
		this.committed = false;
		this.response.getWriter().write(expected);
		assertThat(this.committed).isFalse();
	}

}
