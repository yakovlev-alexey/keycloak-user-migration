package com.danielfrak.code.keycloak.providers.rest.rest;

import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUser;
import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUserService;
import com.danielfrak.code.keycloak.providers.rest.exceptions.RestUserProviderException;
import com.danielfrak.code.keycloak.providers.rest.rest.http.HttpClient;
import com.danielfrak.code.keycloak.providers.rest.rest.http.strategy.BasicAuthHttpClientStrategyBuilder;
import com.danielfrak.code.keycloak.providers.rest.rest.http.strategy.BearerTokenHttpClientStrategyBuilder;
import com.danielfrak.code.keycloak.providers.rest.rest.http.strategy.DefaultHttpClientStrategyBuilder;
import com.danielfrak.code.keycloak.providers.rest.rest.http.strategy.HttpClientStrategy;
import com.danielfrak.code.keycloak.providers.rest.rest.http.strategy.HttpClientStrategyBuilder;
import com.danielfrak.code.keycloak.providers.rest.rest.http.strategy.JwtAuthHttpClientStrategyBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.keycloak.component.ComponentModel;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

import static com.danielfrak.code.keycloak.providers.rest.ConfigurationProperties.*;

public class RestUserService implements LegacyUserService {

    private final String uri;
    private final HttpClient httpClient;
    private final HttpClientStrategyBuilder httpClientStrategyBuilder;
    private final ObjectMapper objectMapper;

    public RestUserService(ComponentModel model, HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = httpClient;
        this.uri = model.getConfig().getFirst(URI_PROPERTY);
        this.objectMapper = objectMapper;

        this.httpClientStrategyBuilder = createHttpClientStrategyBuilder(model);
    }

    @Override
    public Optional<LegacyUser> findByEmail(String email) {
        return findLegacyUser(email)
                .filter(u -> equalsCaseInsensitive(email, u.getEmail()));
    }

    private boolean equalsCaseInsensitive(String a, String b) {
        if (a == null || b == null) {
            return false;
        }

        return a.toUpperCase(Locale.ROOT).equals(b.toUpperCase(Locale.ROOT));
    }

    @Override
    public Optional<LegacyUser> findByUsername(String username) {
        return findLegacyUser(username)
                .filter(u -> equalsCaseInsensitive(username, u.getUsername()));
    }

    private Optional<LegacyUser> findLegacyUser(String usernameOrEmail) {
        var getUsernameUri = String.format("%s/%s", this.uri, usernameOrEmail);
        var strategy = buildHttpClientStrategy(usernameOrEmail);
        try {
            var response = this.httpClient.get(getUsernameUri, strategy);
            if (response.getCode() != HttpStatus.SC_OK) {
                return Optional.empty();
            }
            var legacyUser = objectMapper.readValue(response.getBody(), LegacyUser.class);
            return Optional.ofNullable(legacyUser);
        } catch (RuntimeException | IOException e) {
            throw new RestUserProviderException(e);
        }
    }

    @Override
    public boolean isPasswordValid(String username, String password) {
        var passwordValidationUri = String.format("%s/%s", this.uri, username);
        var dto = new UserPasswordDto(password);
        var strategy = buildHttpClientStrategy(username);
        try {
            var json = objectMapper.writeValueAsString(dto);
            var response = httpClient.post(passwordValidationUri, json, strategy);
            return response.getCode() == HttpStatus.SC_OK;
        } catch (IOException e) {
            throw new RestUserProviderException(e);
        }
    }

    private HttpClientStrategy buildHttpClientStrategy(String context) {
        if (httpClientStrategyBuilder instanceof JwtAuthHttpClientStrategyBuilder) {
            ((JwtAuthHttpClientStrategyBuilder) httpClientStrategyBuilder).setSubject(context);
        }

        return httpClientStrategyBuilder.build();
    }

    private static HttpClientStrategyBuilder createHttpClientStrategyBuilder(ComponentModel model) {
        var basicAuthConfig = model.getConfig().getFirst(API_HTTP_BASIC_ENABLED_PROPERTY);
        var basicAuthEnabled = Boolean.parseBoolean(basicAuthConfig);

        if (basicAuthEnabled) {
            String basicAuthUser = model.getConfig().getFirst(API_HTTP_BASIC_USERNAME_PROPERTY);
            String basicAuthPassword = model.getConfig().getFirst(API_HTTP_BASIC_PASSWORD_PROPERTY);

            return BasicAuthHttpClientStrategyBuilder.create().setCredentials(basicAuthUser, basicAuthPassword);
        }

        var tokenAuthEnabled = Boolean.parseBoolean(model.getConfig().getFirst(API_TOKEN_ENABLED_PROPERTY));
        if (tokenAuthEnabled) {
            String token = model.getConfig().getFirst(API_TOKEN_PROPERTY);

            return BearerTokenHttpClientStrategyBuilder.create().setToken(token);
        }

        boolean jwtAuthEnabled = Boolean.parseBoolean(model.getConfig().getFirst(API_JWT_ENABLED_PROPERTY));
        if (jwtAuthEnabled) {

            String privateKey = model.getConfig().getFirst(API_JWT_PRIVATE_KEY_PROPERTY);
            PrivateKey parsedPrivateKey = getPrivateKey(privateKey);

            if (parsedPrivateKey != null) {
                return JwtAuthHttpClientStrategyBuilder.create().setSigningKey(parsedPrivateKey);
            }
        }

        return DefaultHttpClientStrategyBuilder.create();
    }

    private static PrivateKey getPrivateKey(String privateKey) {
        StringBuilder pkcs8Lines = new StringBuilder();

        BufferedReader rdr = new BufferedReader(new StringReader(privateKey));

        try {
            String line;
            while ((line = rdr.readLine()) != null) {
                pkcs8Lines.append(line);
            }

            String pkcs8Pem = pkcs8Lines.toString();

            pkcs8Pem = pkcs8Pem.replace("-----BEGIN PRIVATE KEY-----", "");
            pkcs8Pem = pkcs8Pem.replace("-----END PRIVATE KEY-----", "");
            pkcs8Pem = pkcs8Pem.replaceAll("\\s+", "");

            byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8Pem);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");

            return kf.generatePrivate(keySpec);
        } catch (Exception e) {
            return null;
        }
    }
}
