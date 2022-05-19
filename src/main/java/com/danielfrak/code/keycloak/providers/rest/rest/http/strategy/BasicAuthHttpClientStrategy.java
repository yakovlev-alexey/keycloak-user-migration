package com.danielfrak.code.keycloak.providers.rest.rest.http.strategy;

import java.nio.charset.StandardCharsets;

import com.danielfrak.code.keycloak.providers.rest.rest.http.AuthorizationHeaderFormats;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.message.BasicHeader;

public final class BasicAuthHttpClientStrategy implements HttpClientStrategy {
        private static final String USERNAME_PASSWORD_FORMAT = "%s:%s";

        private BasicHeader authorizationHeader = null;

        public BasicAuthHttpClientStrategy(String user, String password) {
                if (user == null || user.isBlank() || password == null || password.isBlank()) {
                        return;
                }

                String auth = String.format(USERNAME_PASSWORD_FORMAT, user, password);

                byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(StandardCharsets.ISO_8859_1));
                var headerValue = String.format(AuthorizationHeaderFormats.BASIC_AUTH_FORMAT,
                                new String(encodedAuth, StandardCharsets.ISO_8859_1));

                authorizationHeader = new BasicHeader(HttpHeaders.AUTHORIZATION, headerValue);
        }

        @Override
        public void configure(HttpUriRequest request) {
                if (authorizationHeader != null) {
                        request.setHeader(authorizationHeader);
                }
        }
}
