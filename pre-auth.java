import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Enable OAuth2 Login (Authorization Code Flow)
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/oauth2/authorization/okta")  // Custom Okta login page
                .defaultSuccessUrl("/home")  // Redirect after successful login
                .failureUrl("/login?error=true")  // Redirect on failure
            )
            // Enable OAuth2 Resource Server (JWT)
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())  // Convert JWT claims to authorities
                )
            )
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/user/**").hasAuthority("USER")  // Protect the /user endpoint
                .anyRequest().authenticated()  // All other requests require authentication
            )
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint((request, response, authException) -> {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                })
            );
        
        return http.build();
    }

    // Convert JWT 'groups' or 'roles' claim to authorities
    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("groups");  // Use "groups" or "roles" based on your JWT structure
        grantedAuthoritiesConverter.setAuthorityPrefix("");  // No prefix needed

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }
}
