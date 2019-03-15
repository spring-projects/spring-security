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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.security.web.util.OnCommittedResponseWrapper;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
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

	@Before
	public void setup() throws Exception {
		response = new OnCommittedResponseWrapper(delegate) {
			@Override
			protected void onResponseCommitted() {
				committed = true;
			}
		};
		when(delegate.getWriter()).thenReturn(writer);
		when(delegate.getOutputStream()).thenReturn(out);
	}


	// --- printwriter

	@Test
	public void printWriterHashCode() throws Exception {
		int expected = writer.hashCode();

		assertThat(response.getWriter().hashCode()).isEqualTo(expected);
	}

	@Test
	public void printWriterCheckError() throws Exception {
		boolean expected = true;
		when(writer.checkError()).thenReturn(expected);

		assertThat(response.getWriter().checkError()).isEqualTo(expected);
	}

	@Test
	public void printWriterWriteInt() throws Exception {
		int expected = 1;

		response.getWriter().write(expected);

		verify(writer).write(expected);
	}

	@Test
	public void printWriterWriteCharIntInt() throws Exception {
		char[] buff = new char[0];
		int off = 2;
		int len = 3;

		response.getWriter().write(buff, off, len);

		verify(writer).write(buff, off, len);
	}

	@Test
	public void printWriterWriteChar() throws Exception {
		char[] buff = new char[0];

		response.getWriter().write(buff);

		verify(writer).write(buff);
	}

	@Test
	public void printWriterWriteStringIntInt() throws Exception {
		String s = "";
		int off = 2;
		int len = 3;

		response.getWriter().write(s, off, len);

		verify(writer).write(s, off, len);
	}

	@Test
	public void printWriterWriteString() throws Exception {
		String s = "";

		response.getWriter().write(s);

		verify(writer).write(s);
	}

	@Test
	public void printWriterPrintBoolean() throws Exception {
		boolean b = true;

		response.getWriter().print(b);

		verify(writer).print(b);
	}

	@Test
	public void printWriterPrintChar() throws Exception {
		char c = 1;

		response.getWriter().print(c);

		verify(writer).print(c);
	}

	@Test
	public void printWriterPrintInt() throws Exception {
		int i = 1;

		response.getWriter().print(i);

		verify(writer).print(i);
	}

	@Test
	public void printWriterPrintLong() throws Exception {
		long l = 1;

		response.getWriter().print(l);

		verify(writer).print(l);
	}

	@Test
	public void printWriterPrintFloat() throws Exception {
		float f = 1;

		response.getWriter().print(f);

		verify(writer).print(f);
	}

	@Test
	public void printWriterPrintDouble() throws Exception {
		double x = 1;

		response.getWriter().print(x);

		verify(writer).print(x);
	}

	@Test
	public void printWriterPrintCharArray() throws Exception {
		char[] x = new char[0];

		response.getWriter().print(x);

		verify(writer).print(x);
	}

	@Test
	public void printWriterPrintString() throws Exception {
		String x = "1";

		response.getWriter().print(x);

		verify(writer).print(x);
	}

	@Test
	public void printWriterPrintObject() throws Exception {
		Object x = "1";

		response.getWriter().print(x);

		verify(writer).print(x);
	}

	@Test
	public void printWriterPrintln() throws Exception {
		response.getWriter().println();

		verify(writer).println();
	}

	@Test
	public void printWriterPrintlnBoolean() throws Exception {
		boolean b = true;

		response.getWriter().println(b);

		verify(writer).println(b);
	}

	@Test
	public void printWriterPrintlnChar() throws Exception {
		char c = 1;

		response.getWriter().println(c);

		verify(writer).println(c);
	}

	@Test
	public void printWriterPrintlnInt() throws Exception {
		int i = 1;

		response.getWriter().println(i);

		verify(writer).println(i);
	}

	@Test
	public void printWriterPrintlnLong() throws Exception {
		long l = 1;

		response.getWriter().println(l);

		verify(writer).println(l);
	}

	@Test
	public void printWriterPrintlnFloat() throws Exception {
		float f = 1;

		response.getWriter().println(f);

		verify(writer).println(f);
	}

	@Test
	public void printWriterPrintlnDouble() throws Exception {
		double x = 1;

		response.getWriter().println(x);

		verify(writer).println(x);
	}

	@Test
	public void printWriterPrintlnCharArray() throws Exception {
		char[] x = new char[0];

		response.getWriter().println(x);

		verify(writer).println(x);
	}

	@Test
	public void printWriterPrintlnString() throws Exception {
		String x = "1";

		response.getWriter().println(x);

		verify(writer).println(x);
	}

	@Test
	public void printWriterPrintlnObject() throws Exception {
		Object x = "1";

		response.getWriter().println(x);

		verify(writer).println(x);
	}

	@Test
	public void printWriterPrintfStringObjectVargs() throws Exception {
		String format = "format";
		Object[] args = new Object[] { "1" };

		response.getWriter().printf(format, args);

		verify(writer).printf(format, args);
	}

	@Test
	public void printWriterPrintfLocaleStringObjectVargs() throws Exception {
		Locale l = Locale.US;
		String format = "format";
		Object[] args = new Object[] { "1" };

		response.getWriter().printf(l, format, args);

		verify(writer).printf(l, format, args);
	}

	@Test
	public void printWriterFormatStringObjectVargs() throws Exception {
		String format = "format";
		Object[] args = new Object[] { "1" };

		response.getWriter().format(format, args);

		verify(writer).format(format, args);
	}

	@Test
	public void printWriterFormatLocaleStringObjectVargs() throws Exception {
		Locale l = Locale.US;
		String format = "format";
		Object[] args = new Object[] { "1" };

		response.getWriter().format(l, format, args);

		verify(writer).format(l, format, args);
	}


	@Test
	public void printWriterAppendCharSequence() throws Exception {
		String x = "a";

		response.getWriter().append(x);

		verify(writer).append(x);
	}

	@Test
	public void printWriterAppendCharSequenceIntInt() throws Exception {
		String x = "abcdef";
		int start = 1;
		int end = 3;

		response.getWriter().append(x, start, end);

		verify(writer).append(x, start, end);
	}


	@Test
	public void printWriterAppendChar() throws Exception {
		char x = 1;

		response.getWriter().append(x);

		verify(writer).append(x);
	}

	// servletoutputstream


	@Test
	public void outputStreamHashCode() throws Exception {
		int expected = out.hashCode();

		assertThat(response.getOutputStream().hashCode()).isEqualTo(expected);
	}

	@Test
	public void outputStreamWriteInt() throws Exception {
		int expected = 1;

		response.getOutputStream().write(expected);

		verify(out).write(expected);
	}

	@Test
	public void outputStreamWriteByte() throws Exception {
		byte[] expected = new byte[0];

		response.getOutputStream().write(expected);

		verify(out).write(expected);
	}

	@Test
	public void outputStreamWriteByteIntInt() throws Exception {
		int start = 1;
		int end = 2;
		byte[] expected = new byte[0];

		response.getOutputStream().write(expected, start, end);

		verify(out).write(expected, start, end);
	}

	@Test
	public void outputStreamPrintBoolean() throws Exception {
		boolean b = true;

		response.getOutputStream().print(b);

		verify(out).print(b);
	}

	@Test
	public void outputStreamPrintChar() throws Exception {
		char c = 1;

		response.getOutputStream().print(c);

		verify(out).print(c);
	}

	@Test
	public void outputStreamPrintInt() throws Exception {
		int i = 1;

		response.getOutputStream().print(i);

		verify(out).print(i);
	}

	@Test
	public void outputStreamPrintLong() throws Exception {
		long l = 1;

		response.getOutputStream().print(l);

		verify(out).print(l);
	}

	@Test
	public void outputStreamPrintFloat() throws Exception {
		float f = 1;

		response.getOutputStream().print(f);

		verify(out).print(f);
	}

	@Test
	public void outputStreamPrintDouble() throws Exception {
		double x = 1;

		response.getOutputStream().print(x);

		verify(out).print(x);
	}

	@Test
	public void outputStreamPrintString() throws Exception {
		String x = "1";

		response.getOutputStream().print(x);

		verify(out).print(x);
	}

	@Test
	public void outputStreamPrintln() throws Exception {
		response.getOutputStream().println();

		verify(out).println();
	}

	@Test
	public void outputStreamPrintlnBoolean() throws Exception {
		boolean b = true;

		response.getOutputStream().println(b);

		verify(out).println(b);
	}

	@Test
	public void outputStreamPrintlnChar() throws Exception {
		char c = 1;

		response.getOutputStream().println(c);

		verify(out).println(c);
	}

	@Test
	public void outputStreamPrintlnInt() throws Exception {
		int i = 1;

		response.getOutputStream().println(i);

		verify(out).println(i);
	}

	@Test
	public void outputStreamPrintlnLong() throws Exception {
		long l = 1;

		response.getOutputStream().println(l);

		verify(out).println(l);
	}

	@Test
	public void outputStreamPrintlnFloat() throws Exception {
		float f = 1;

		response.getOutputStream().println(f);

		verify(out).println(f);
	}

	@Test
	public void outputStreamPrintlnDouble() throws Exception {
		double x = 1;

		response.getOutputStream().println(x);

		verify(out).println(x);
	}

	@Test
	public void outputStreamPrintlnString() throws Exception {
		String x = "1";

		response.getOutputStream().println(x);

		verify(out).println(x);
	}

	// The amount of content specified in the setContentLength method of the response
	// has been greater than zero and has been written to the response.

	// gh-3823
	@Test
	public void contentLengthPrintWriterWriteNullCommits() throws Exception {
		String expected = null;
		this.response.setContentLength(String.valueOf(expected).length() + 1);

		this.response.getWriter().write(expected);

		assertThat(this.committed).isFalse();

		this.response.getWriter().write("a");

		assertThat(this.committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterWriteIntCommits() throws Exception {
		int expected = 1;
		response.setContentLength(String.valueOf(expected).length());

		response.getWriter().write(expected);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterWriteIntMultiDigitCommits() throws Exception {
		int expected = 10000;
		response.setContentLength(String.valueOf(expected).length());

		response.getWriter().write(expected);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPlus1PrintWriterWriteIntMultiDigitCommits() throws Exception {
		int expected = 10000;
		response.setContentLength(String.valueOf(expected).length() + 1);

		response.getWriter().write(expected);

		assertThat(committed).isFalse();

		response.getWriter().write(1);

		assertThat(committed).isTrue();
	}


	@Test
	public void contentLengthPrintWriterWriteCharIntIntCommits() throws Exception {
		char[] buff = new char[0];
		int off = 2;
		int len = 3;
		response.setContentLength(3);

		response.getWriter().write(buff, off, len);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterWriteCharCommits() throws Exception {
		char[] buff = new char[4];
		response.setContentLength(buff.length);

		response.getWriter().write(buff);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterWriteStringIntIntCommits() throws Exception {
		String s = "";
		int off = 2;
		int len = 3;
		response.setContentLength(3);

		response.getWriter().write(s, off, len);

		assertThat(committed).isTrue();
	}


	@Test
	public void contentLengthPrintWriterWriteStringCommits() throws IOException {
		String body = "something";
		response.setContentLength(body.length());

		response.getWriter().write(body);

		assertThat(committed).isTrue();
	}

	@Test
	public void printWriterWriteStringContentLengthCommits() throws IOException {
		String body = "something";
		response.getWriter().write(body);

		response.setContentLength(body.length());

		assertThat(committed).isTrue();
	}

	@Test
	public void printWriterWriteStringDoesNotCommit() throws IOException {
		String body = "something";

		response.getWriter().write(body);

		assertThat(committed).isFalse();
	}

	@Test
	public void contentLengthPrintWriterPrintBooleanCommits() throws Exception {
		boolean b = true;
		response.setContentLength(1);

		response.getWriter().print(b);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintCharCommits() throws Exception {
		char c = 1;
		response.setContentLength(1);

		response.getWriter().print(c);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintIntCommits() throws Exception {
		int i = 1234;
		response.setContentLength(String.valueOf(i).length());

		response.getWriter().print(i);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintLongCommits() throws Exception {
		long l = 12345;
		response.setContentLength(String.valueOf(l).length());

		response.getWriter().print(l);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintFloatCommits() throws Exception {
		float f = 12345;
		response.setContentLength(String.valueOf(f).length());

		response.getWriter().print(f);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintDoubleCommits() throws Exception {
		double x = 1.2345;
		response.setContentLength(String.valueOf(x).length());

		response.getWriter().print(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintCharArrayCommits() throws Exception {
		char[] x = new char[10];
		response.setContentLength(x.length);

		response.getWriter().print(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintStringCommits() throws Exception {
		String x = "12345";
		response.setContentLength(x.length());

		response.getWriter().print(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintObjectCommits() throws Exception {
		Object x = "12345";
		response.setContentLength(String.valueOf(x).length());

		response.getWriter().print(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnCommits() throws Exception {
		response.setContentLength(NL.length());

		response.getWriter().println();

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnBooleanCommits() throws Exception {
		boolean b = true;
		response.setContentLength(1);

		response.getWriter().println(b);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnCharCommits() throws Exception {
		char c = 1;
		response.setContentLength(1);

		response.getWriter().println(c);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnIntCommits() throws Exception {
		int i = 12345;
		response.setContentLength(String.valueOf(i).length());

		response.getWriter().println(i);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnLongCommits() throws Exception {
		long l = 12345678;
		response.setContentLength(String.valueOf(l).length());

		response.getWriter().println(l);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnFloatCommits() throws Exception {
		float f = 1234;
		response.setContentLength(String.valueOf(f).length());

		response.getWriter().println(f);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnDoubleCommits() throws Exception {
		double x = 1;
		response.setContentLength(String.valueOf(x).length());

		response.getWriter().println(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnCharArrayCommits() throws Exception {
		char[] x = new char[20];
		response.setContentLength(x.length);

		response.getWriter().println(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnStringCommits() throws Exception {
		String x = "1";
		response.setContentLength(String.valueOf(x).length());

		response.getWriter().println(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterPrintlnObjectCommits() throws Exception {
		Object x = "1";
		response.setContentLength(String.valueOf(x).length());

		response.getWriter().println(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterAppendCharSequenceCommits() throws Exception {
		String x = "a";
		response.setContentLength(String.valueOf(x).length());

		response.getWriter().append(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterAppendCharSequenceIntIntCommits() throws Exception {
		String x = "abcdef";
		int start = 1;
		int end = 3;
		response.setContentLength(end - start);

		response.getWriter().append(x, start, end);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPrintWriterAppendCharCommits() throws Exception {
		char x = 1;
		response.setContentLength(1);

		response.getWriter().append(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamWriteIntCommits() throws Exception {
		int expected = 1;
		response.setContentLength(String.valueOf(expected).length());

		response.getOutputStream().write(expected);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamWriteIntMultiDigitCommits() throws Exception {
		int expected = 10000;
		response.setContentLength(String.valueOf(expected).length());

		response.getOutputStream().write(expected);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthPlus1OutputStreamWriteIntMultiDigitCommits() throws Exception {
		int expected = 10000;
		response.setContentLength(String.valueOf(expected).length() + 1);

		response.getOutputStream().write(expected);

		assertThat(committed).isFalse();

		response.getOutputStream().write(1);

		assertThat(committed).isTrue();
	}

	// gh-171
	@Test
	public void contentLengthPlus1OutputStreamWriteByteArrayMultiDigitCommits() throws Exception {
		String expected = "{\n" +
				"  \"parameterName\" : \"_csrf\",\n" +
				"  \"token\" : \"06300b65-c4aa-4c8f-8cda-39ee17f545a0\",\n" +
				"  \"headerName\" : \"X-CSRF-TOKEN\"\n" +
				"}";
		response.setContentLength(expected.length() + 1);

		response.getOutputStream().write(expected.getBytes());

		assertThat(committed).isFalse();

		response.getOutputStream().write("1".getBytes("UTF-8"));

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintBooleanCommits() throws Exception {
		boolean b = true;
		response.setContentLength(1);

		response.getOutputStream().print(b);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintCharCommits() throws Exception {
		char c = 1;
		response.setContentLength(1);

		response.getOutputStream().print(c);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintIntCommits() throws Exception {
		int i = 1234;
		response.setContentLength(String.valueOf(i).length());

		response.getOutputStream().print(i);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintLongCommits() throws Exception {
		long l = 12345;
		response.setContentLength(String.valueOf(l).length());

		response.getOutputStream().print(l);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintFloatCommits() throws Exception {
		float f = 12345;
		response.setContentLength(String.valueOf(f).length());

		response.getOutputStream().print(f);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintDoubleCommits() throws Exception {
		double x = 1.2345;
		response.setContentLength(String.valueOf(x).length());

		response.getOutputStream().print(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintStringCommits() throws Exception {
		String x = "12345";
		response.setContentLength(x.length());

		response.getOutputStream().print(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnCommits() throws Exception {
		response.setContentLength(NL.length());

		response.getOutputStream().println();

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnBooleanCommits() throws Exception {
		boolean b = true;
		response.setContentLength(1);

		response.getOutputStream().println(b);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnCharCommits() throws Exception {
		char c = 1;
		response.setContentLength(1);

		response.getOutputStream().println(c);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnIntCommits() throws Exception {
		int i = 12345;
		response.setContentLength(String.valueOf(i).length());

		response.getOutputStream().println(i);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnLongCommits() throws Exception {
		long l = 12345678;
		response.setContentLength(String.valueOf(l).length());

		response.getOutputStream().println(l);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnFloatCommits() throws Exception {
		float f = 1234;
		response.setContentLength(String.valueOf(f).length());

		response.getOutputStream().println(f);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnDoubleCommits() throws Exception {
		double x = 1;
		response.setContentLength(String.valueOf(x).length());

		response.getOutputStream().println(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthOutputStreamPrintlnStringCommits() throws Exception {
		String x = "1";
		response.setContentLength(String.valueOf(x).length());

		response.getOutputStream().println(x);

		assertThat(committed).isTrue();
	}

	@Test
	public void contentLengthDoesNotCommit() throws IOException {
		String body = "something";

		response.setContentLength(body.length());

		assertThat(committed).isFalse();
	}

	@Test
	public void contentLengthOutputStreamWriteStringCommits() throws IOException {
		String body = "something";
		response.setContentLength(body.length());

		response.getOutputStream().print(body);

		assertThat(committed).isTrue();
	}

	@Test
	public void addHeaderContentLengthPrintWriterWriteStringCommits() throws Exception {
		int expected = 1234;
		response.addHeader("Content-Length", String.valueOf(String.valueOf(expected).length()));

		response.getWriter().write(expected);

		assertThat(committed).isTrue();
	}

	@Test
	public void bufferSizePrintWriterWriteCommits() throws Exception {
		String expected = "1234567890";
		when(response.getBufferSize()).thenReturn(expected.length());

		response.getWriter().write(expected);

		assertThat(committed).isTrue();
	}

	@Test
	public void bufferSizeCommitsOnce() throws Exception {
		String expected = "1234567890";
		when(response.getBufferSize()).thenReturn(expected.length());

		response.getWriter().write(expected);

		assertThat(committed).isTrue();

		committed = false;

		response.getWriter().write(expected);

		assertThat(committed).isFalse();
	}
}
