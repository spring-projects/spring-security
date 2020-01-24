CREATE TABLE oauth2AuthorizedClient (
  clientRegistrationId varchar(100) NOT NULL,
  principalName varchar(100) NOT NULL,
  accessTokenType varchar(75) NOT NULL,
  accessTokenValue varchar(7000) NOT NULL,
  accessTokenIssuedAt timestamp NOT NULL,
  accessTokenExpiresAt timestamp NOT NULL,
  accessTokenScopes varchar(1000) DEFAULT NULL,
  refreshTokenValue varchar(7000) DEFAULT NULL,
  refreshTokenIssuedAt timestamp DEFAULT NULL,
  createdAt timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
  PRIMARY KEY (clientRegistrationId, principalName)
);
