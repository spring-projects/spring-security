<%@ taglib prefix="c" uri="http://java.sun.com/jstl/core_rt"%>

<h1>Accounts</h1>

<a href="index.jsp">Home</a><br><br>

<table>
<tr>
<td><b>ID</b></td>
<td><b>Holder</b></td>
<td><b>Balance</b></td>
<td><b>Overdraft</b></td>
<td><b>Operations</b></td>
</tr>
<c:forEach var="account" items="${accounts}">
  <tr>
  <td>
      <c:out value="${account.id}"/>
  </td>
  <td>
      <c:out value="${account.holder}"/>
  </td>
  <td>
      <c:out value="${account.balance}"/>
  </td>
  <td>
      <c:out value="${account.overdraft}"/>
  </td>
  <td>
      <a href="post.html?id=<c:out value="${account.id}"/>&amount=-20.00">-$20</a>
      <a href="post.html?id=<c:out value="${account.id}"/>&amount=-5.00">-$5</a>
      <a href="post.html?id=<c:out value="${account.id}"/>&amount=5.00">+$5</a>
      <a href="post.html?id=<c:out value="${account.id}"/>&amount=20.00">+$20</a>
  </td>
  </tr>
</c:forEach>
</table>

<p><a href="j_spring_security_logout">Logout</a>
