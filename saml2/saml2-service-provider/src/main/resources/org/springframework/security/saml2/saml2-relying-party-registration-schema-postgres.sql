CREATE TABLE saml2_relying_party_registration
(
    id                                       VARCHAR(200) NOT NULL,
    entity_id                                VARCHAR(1000),
    name_id_format                           VARCHAR(200),
    acs_location                             VARCHAR(1000),
    acs_binding                              VARCHAR(200),
    signing_credentials BYTEA,
    decryption_credentials BYTEA,
    singlelogout_url                         VARCHAR(1000),
    singlelogout_response_url                VARCHAR(1000),
    singlelogout_binding                     VARCHAR(200),
    assertingparty_entity_id                 VARCHAR(1000),
    assertingparty_metadata_uri              VARCHAR(1000),
    assertingparty_singlesignon_url          VARCHAR(1000),
    assertingparty_singlesignon_binding      VARCHAR(200),
    assertingparty_singlesignon_sign_request VARCHAR(1000),
    assertingparty_verification_credentials BYTEA,
    assertingparty_singlelogout_url          VARCHAR(1000),
    assertingparty_singlelogout_response_url VARCHAR(1000),
    assertingparty_singlelogout_binding      VARCHAR(200),
    PRIMARY KEY (id)
);
