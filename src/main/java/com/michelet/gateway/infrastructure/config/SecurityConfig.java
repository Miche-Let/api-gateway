package com.michelet.gateway.infrastructure.config;

import com.michelet.gateway.infrastructure.security.GatewayRoleConverter;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http, GatewayRoleConverter roleConverter){
        ReactiveJwtAuthenticationConverter jwtAuthenticationConverter = new ReactiveJwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(roleConverter);
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(
                        exchanges-> exchanges.pathMatchers(
                                "/api/*/auth/login",
                                "/api/*/auth/reissue",
                                "/api/*/users/signup", "/actuator/health", "/actuator/info"
                        ).permitAll()
                                .pathMatchers("/api/*/admin/**").hasRole("MASTER")
                                .anyExchange().authenticated()

                )
                .oauth2ResourceServer(oauth2-> oauth2.jwt(
                        jwtSpec -> jwtSpec.jwtAuthenticationConverter(jwtAuthenticationConverter)
                )).build();
    }

    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder(@Value("${jwt.secret}") String secret) {
        SecretKey secretKey = new SecretKeySpec(
                secret.getBytes(StandardCharsets.UTF_8),
                "HmacSHA256"
        );

        return NimbusReactiveJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
    }


}
