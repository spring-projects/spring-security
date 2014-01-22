<%@ include file="/WEB-INF/jsp/include.jsp" %>
<html>
<head><title>Add New Contact</title></head>
<body>
<h1>Add Contact</h1>
<form method="post">
  <table width="95%" bgcolor="f8f8ff" border="0" cellspacing="0" cellpadding="5">
    <tr>
      <td alignment="right" width="20%">Name:</td>
      <spring:bind path="webContact.name">
        <td width="20%">
          <input type="text" name="name" value="<c:out value="${status.value}"/>">
        </td>
        <td width="60%">
          <font color="red"><c:out value="${status.errorMessage}"/></font>
        </td>
      </spring:bind>
    </tr>
    <tr>
      <td alignment="right" width="20%">Email:</td>
      <spring:bind path="webContact.email">
        <td width="20%">
          <input type="text" name="email" value="<c:out value="${status.value}"/>">
        </td>
        <td width="60%">
          <font color="red"><c:out value="${status.errorMessage}"/></font>
        </td>
      </spring:bind>
    </tr>
  </table>
  <br>
  <spring:hasBindErrors name="webContact">
    <b>Please fix all errors!</b>
  </spring:hasBindErrors>
  <br><br>

  <input type="hidden" name="<c:out value="${_csrf.parameterName}"/>" value="<c:out value="${_csrf.token}"/>"/>
  <input name="execute" type="submit" alignment="center" value="Execute">
</form>
<a href="<c:url value="../hello.htm"/>">Home</a>
</body>
</html>
