import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // OAuth2 Login (Authorization Code Flow)
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/oauth2/authorization/okta")  // Custom Okta login page
                .defaultSuccessUrl("/home")  // Redirect after successful login
            )
            // OAuth2 Resource Server (JWT)
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())  // Convert JWT claims to authorities
                )
            )
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/user/**").hasAuthority("USER")  // Example endpoint protection
                .anyRequest().authenticated()
            );
        return http.build();
    }

    // Convert JWT 'groups' or 'roles' claim to authorities
    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("groups");  // or "roles"
        grantedAuthoritiesConverter.setAuthorityPrefix("");  // No prefix needed

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }
}
