package sit.int204.jwtdemo.entities.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.rest.webmvc.ResourceNotFoundException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import sit.int204.jwtdemo.entities.entities.AuthUserDetail;
import sit.int204.jwtdemo.entities.entities.User;
import sit.int204.jwtdemo.entities.repositories.UserRepository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

//ที่ใช้ในการโหลดข้อมูลผู้ใช้จากฐานข้อมูลและแปลงข้อมูลเป็น UserDetails
@Service
public class JwtUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override //spring จะ load user มาจาก source ของเรา
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { //ดึงมาจาก database
        User user = userRepository.findByUsernameOrEmail(username)  //ค้นหาจาก username หรือ email
                .orElseThrow(() -> new UsernameNotFoundException(username)); //ถ้าหาไม่เจอ throw exception
        return new AuthUserDetail(user.getId(), user.getUsername(), user.getPassword() //ถ้าเจอก็จะได้ object user มา
                , getAuthorities(user.getRoles()));
    }

    //ใช้สำหรับค้นหาผู้ใช้จากฐานข้อมูลโดยใช้ id และถ้าไม่พบจะโยน ResourceNotFoundException.
    public UserDetails loadUserById(Long id) {
        User user = userRepository.findById(id).orElseThrow(
                () -> new ResourceNotFoundException("User id " + id + " does not exist")
        );
        return new AuthUserDetail(user.getId(), user.getUsername(), user.getPassword()
                , getAuthorities(user.getRoles())
        );
    }

    //แปลงข้อมูล roles (ที่แยกด้วยเครื่องหมายจุลภาค) ให้เป็น GrantedAuthority ซึ่งใช้ใน Spring Security เพื่อกำหนดสิทธิ์การเข้าถึง.
    public static List<GrantedAuthority> getAuthorities(String rolesAsCommaSeparated) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        Arrays.asList(rolesAsCommaSeparated.split(",")).forEach( //แยกด้วย comma วนลูป Array
                role -> authorities.add(getAuthority(role))
        );
        return authorities;
    }

    //แปลงแต่ละ role เป็น SimpleGrantedAuthority ซึ่งเป็นคลาสที่ Spring Security ใช้ในการจัดการสิทธิ์.
    private static GrantedAuthority getAuthority(String role) {
        return new SimpleGrantedAuthority(role); //ได้role แล้วส่งมานี้
    }
}
