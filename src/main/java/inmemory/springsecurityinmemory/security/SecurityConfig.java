package inmemory.springsecurityinmemory.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity  //Security filter chain uygulamak için kullanılır.
@EnableMethodSecurity// control sınıfındaki methodların securiysini sağlayan annotation
public class SecurityConfig {
    @Bean
    //public PasswordEncoder passwordEncoder() {}  // SHA kullanır
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService users() {
        UserDetails user1 = User.builder()
                .username("fsk")
                .password(passwordEncoder().encode("pass"))
                .roles("USER")
                .build();

        UserDetails user2 = User.builder()
                .username("oguz")
                .password(passwordEncoder().encode("pass"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user1, user2);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                //// X-Frame-Options başlığını devre dışı bırakır. Bu, sayfanın diğer siteler tarafından iframe içine yerleştirilmesini sağlar.
                .headers(x->x.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                // CSRF (Cross-Site Request Forgery) korumasını devre dışı bırakır.
                .csrf(AbstractHttpConfigurer::disable)
                // Form tabanlı oturum açma (form login) özelliğini devre dışı bırakır.
                .formLogin(AbstractHttpConfigurer::disable)
                // İsteklerin yetkilendirilmesini yapılandırır.
                .authorizeHttpRequests(x-> x.requestMatchers("/public/**","/auth/**").permitAll())
                //BU YOL İLEDE YAPABİLİRSİN FAKAT ANNOTATİON DAHA GÜZEL BENCE
                //.authorizeHttpRequests(x->x.requestMatchers("/private/user/**").hasRole("USER")) // ATTENTİON "/PRİVATE" KISMINI DEĞİŞTİR.
                //.authorizeHttpRequests(x->x.requestMatchers("/private/admin/**").hasRole("ADMIN"))
                .authorizeHttpRequests((x->x.anyRequest().authenticated()))
                // Temel HTTP kimlik doğrulamasını (HTTP Basic Authentication) yapılandırır. Varsayılan ayarlarla yapılandırılır.
                .httpBasic((Customizer.withDefaults()));
    // public ve aut olanlar hariç diğer herşeye yalnız authenticate olanlar erişebilir.
        return  http.build();

    }
}
