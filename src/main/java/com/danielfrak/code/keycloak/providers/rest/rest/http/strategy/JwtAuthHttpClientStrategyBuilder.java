package com.danielfrak.code.keycloak.providers.rest.rest.http.strategy;

import java.security.Key;

public final class JwtAuthHttpClientStrategyBuilder implements HttpClientStrategyBuilder {
        private Key signingKey;
        private String subject;

        private JwtAuthHttpClientStrategyBuilder() {
        }

        public static JwtAuthHttpClientStrategyBuilder create() {
                return new JwtAuthHttpClientStrategyBuilder();
        }

        public JwtAuthHttpClientStrategyBuilder setSigningKey(Key key) {
                signingKey = key;
                return this;
        }

        public JwtAuthHttpClientStrategyBuilder setSubject(String subject) {
                this.subject = subject;
                return this;
        }

        public JwtAuthHttpClientStrategy build() {
                if (subject == null) {
                        return new JwtAuthHttpClientStrategy(signingKey);
                }

                return new JwtAuthHttpClientStrategy(signingKey, subject);
        }
}
