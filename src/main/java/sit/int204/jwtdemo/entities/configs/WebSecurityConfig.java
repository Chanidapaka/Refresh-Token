package sit.int204.jwtdemo.entities.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import sit.int204.jwtdemo.entities.service.JwtUserDetailsService;

//ซึ่งใช้ในการตั้งค่าการควบคุมการเข้าถึง (access control) สำหรับแอปพลิเคชันที่ใช้ Spring Boot โดยตั้งค่าต่างๆ ผ่าน HttpSecurity ใน Spring Security
@EnableWebSecurity //ใช้ในการเปิดใช้งาน Spring Security ในแอปพลิเคชัน ทำให้สามารถตั้งค่าความปลอดภัยของเว็บแอปพลิเคชันได้
@Configuration //ที่ใช้ในการกำหนดการตั้งค่าต่างๆ ของ Spring
public class WebSecurityConfig {

    //การใช้ HttpSecurity ช่วยให้สามารถกำหนดกฎการอนุญาต (authorization) การป้องกัน CSRF, และการจัดการ session ได้
    @Bean //ที่ใช้กำหนดค่าการตั้งค่า HttpSecurity ซึ่งเป็นตัวควบคุมการตั้งค่าความปลอดภัยของแอปพลิเคชัน
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        //ปิดการตั้งค่า frame options เพื่อไม่ให้ error
        http.headers(httpSecurityHeadersConfigurer ->
                httpSecurityHeadersConfigurer.frameOptions(frameOptionsConfig ->
                        frameOptionsConfig.disable()));

        //ปิดการตรวจสอบ Cross-Site Request Forgery (CSRF) ซึ่งปกติแล้ว Spring Security จะเปิดใช้งาน CSRF protection
        //แต่ในกรณีนี้ปิดการป้องกัน CSRF เนื่องจากอาจใช้ API แบบ stateless หรือการตั้งค่าอื่นๆ ที่ไม่ต้องการ CSRF protection
        http.csrf(crsf -> crsf.disable())

                //กำหนดให้ทุกคำขอ (request) ในแอปพลิเคชันสามารถเข้าถึงได้โดยไม่ต้องมีการตรวจสอบสิทธิ์ (ทุกหน้าสามารถเข้าถึงได้ไม่จำกัด)
                .authorizeHttpRequests((requests) -> requests
                        .anyRequest().permitAll()
                )

                //กำหนด session ให้เป็น stateless คือแอปพลิเคชันจะไม่เก็บสถานะของ session ระหว่างคำขอ (request) ทุกคำขอจะไม่ถูกผูกกับ session ใดๆ
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        //สร้างและคืนค่าการตั้งค่าความปลอดภัยที่ถูกกำหนดใน http เพื่อให้ Spring Security ใช้ในการรักษาความปลอดภัยของแอปพลิเคชัน
        return http.build();
    }

    //เพื่อที่จะทำ Autowire ได้
    //ใช้ในการจัดการการตรวจสอบการเข้าสู่ระบบของผู้ใช้
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    //เพื่อที่จะทำ jwtUserDetailsService
    //เมธอดนี้ตั้งค่าการใช้ PasswordEncoder ซึ่งจะใช้ในการเข้ารหัสและตรวจสอบรหัสผ่านของผู้ใช้
    @Bean
    public AuthenticationProvider authenticationProvider(JwtUserDetailsService jwtUserDetailsService) {
        // คือการใช้การตรวจสอบผู้ใช้จากฐานข้อมูล.
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(jwtUserDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;
    }

    //เมธอดนี้กำหนด PasswordEncoder ซึ่งใช้ในการเข้ารหัสรหัสผ่านของผู้ใช้ก่อนที่จะเก็บในฐานข้อมูลและตรวจสอบเวลาที่ผู้ใช้ทำการล็อกอิน.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(); //ใช้ Argon2PasswordEncoder ซึ่งเป็นหนึ่งในวิธีการเข้ารหัสที่มีความปลอดภัยสูง.
    }
}
