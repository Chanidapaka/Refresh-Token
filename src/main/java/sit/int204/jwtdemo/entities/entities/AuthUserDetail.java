package sit.int204.jwtdemo.entities.entities;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;

//คลาสที่ใช้ในการเก็บข้อมูลผู้ใช้ เช่น username, password, และ authorities (สิทธิ์การเข้าถึง)
@Getter
public class AuthUserDetail extends org.springframework.security.core.userdetails.User {
    private Long id;

    //คอนสตรัคเตอร์นี้จะรับ id, username, และ password
    //และตั้งค่าผู้ใช้โดยใช้ new ArrayList<GrantedAuthority>() สำหรับ authorities (ไม่มีสิทธิ์เริ่มต้น)
    public AuthUserDetail(Long id, String username, String password) {
        this(id, username, password,new ArrayList<GrantedAuthority>());
    }

    //คอนสตรัคเตอร์นี้จะรับ id, username, password, และ authorities (สิทธิ์ที่ผู้ใช้มี)
    //และส่งผ่านค่าเหล่านี้ให้กับคลาส User ของ Spring Security โดยใช้ super(username, password, authorities)
    public AuthUserDetail(Long id, String username, String password
            , Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
        this.id = id;
    }
}
