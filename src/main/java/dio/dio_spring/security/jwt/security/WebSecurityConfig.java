package dio.dio_spring.security.jwt.security;

import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@EnableWebSecurity

public class WebSecurityConfig {

    // Encoder para senhas
    @Bean
    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    // Lista de caminhos permitidos para o Swagger
    private static final String[] SWAGGER_WHITELIST = {
            "/v2/api-docs",
            "/swagger-resources",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/webjars/**"
    };

    // Configuração do SecurityFilterChain
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .headers().frameOptions().disable() // Para permitir o uso do H2 Console
                .and()
                .cors().and().csrf().disable() // Desabilita CORS e CSRF
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Sem estado para APIs
                .and()
                .authorizeRequests()
                .requestMatchers(SWAGGER_WHITELIST).permitAll() // Libera acesso ao Swagger
                .requestMatchers("/h2-console/**").permitAll() // Libera acesso ao H2 Console
                .requestMatchers(HttpMethod.POST, "/login").permitAll() // Permite o login sem autenticação
                .requestMatchers(HttpMethod.POST, "/users").permitAll() // Permite a criação de usuários
                .requestMatchers(HttpMethod.GET, "/users").hasAnyRole("USERS", "MANAGERS") // Restringe acesso aos usuários com roles apropriadas
                .requestMatchers("/managers").hasRole("MANAGERS") // Restringe acesso apenas aos usuários com role MANAGERS
                .anyRequest().authenticated() // Qualquer outra requisição precisa de autenticação
                .and()
                .addFilterBefore(new JWTFilter(), UsernamePasswordAuthenticationFilter.class) // Adiciona o filtro JWT antes do UsernamePasswordAuthenticationFilter
                .httpBasic(); // Habilita autenticação básica

        return http.build();
    }




    // Habilitando o acesso ao H2 Database na web
    @Bean
    public ServletRegistrationBean<?> h2servletRegistration() {
        ServletRegistrationBean<?> registrationBean = new ServletRegistrationBean<>(new org.h2.server.web.WebServlet());
        registrationBean.addUrlMappings("/h2-console/*");
        return registrationBean;
    }
}
