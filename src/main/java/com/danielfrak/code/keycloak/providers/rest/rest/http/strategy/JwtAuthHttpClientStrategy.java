package com.danielfrak.code.keycloak.providers.rest.rest.http.strategy;

import java.security.Key;

import com.danielfrak.code.keycloak.providers.rest.rest.http.AuthorizationHeaderFormats;

import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.HttpUriRequest;

import io.jsonwebtoken.Jwts;

public class JwtAuthHttpClientStrategy implements HttpClientStrategy {
        private Key key;
        private String subject;

        public JwtAuthHttpClientStrategy(Key key, String subject) {
                this.key = key;
                this.subject = subject;
        }

        public JwtAuthHttpClientStrategy(Key key) {
                this.key = key;
        }

        @Override
        public void configure(HttpUriRequest request) {
                String jwt = buildJwtString(request);

                request.addHeader(HttpHeaders.AUTHORIZATION,
                                String.format(AuthorizationHeaderFormats.BEARER_FORMAT, jwt));
        }

        private String buildJwtString(HttpUriRequest request) {
                var subject = this.subject == null ? request.getURI().toString() : this.subject;

                return Jwts.builder().setSubject(subject).signWith(key).compact();
        }
}
