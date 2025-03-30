package sit.int204.jwtdemo.entities.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import sit.int204.jwtdemo.entities.Dto.AccessToken;
import sit.int204.jwtdemo.entities.Dto.JwtRequestUser;
import sit.int204.jwtdemo.entities.entities.User;
import sit.int204.jwtdemo.entities.repositories.UserRepository;
import sit.int204.jwtdemo.entities.utils.JwtUtils;
import sit.int204.jwtdemo.entities.utils.TokenType;

import java.util.List;
import java.util.Map;

@Service
public class UserService {
    //Add authenticate()
    @Autowired
    private AuthenticationManager authenticationManager; // -> ตัวนี้ authen
    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserRepository userRepo;
    //ถ้าไม่มีข้อมูลซ้ำ จะมีการเข้ารหัสรหัสผ่านของผู้ใช้โดยใช้ Argon2PasswordEncoder และบันทึกข้อมูลผู้ใช้ลงในฐานข้อมูล
    private Argon2PasswordEncoder passwordEncoder =
            new Argon2PasswordEncoder(
                    16, 16,
                    8, 1024*128, 2);

    //ฟังก์ชันนี้ใช้ค้นหาผู้ใช้จากฐานข้อมูลโดยใช้ id
    //ถ้าพบผู้ใช้ที่มี id ตรงกับที่ส่งเข้ามา จะคืนค่าผู้ใช้ (User) ที่ตรงกัน  //ถ้าไม่พบผู้ใช้ จะคืนค่าเป็น null
    public User findUserById(Long id) {
        return userRepo.findById(id).orElse(null);
    }

    //ฟังก์ชันนี้ใช้ตรวจสอบว่า username หรือ email ของผู้ใช้มีอยู่ในฐานข้อมูลแล้วหรือไม่ โดยเรียกใช้ userRepo.existsUserByUsernameOrEmail()
    private void checkDuplication(User user) {
        if (userRepo.existsUserByUsernameOrEmail(
                user.getUsername(), user.getEmail())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, //ถ้ามีข้อมูลซ้ำ จะโยน"User name or Email already exist !!!
                    "User name or Email already exist !!! ("
                            + user.getUsername() + ", " + user.getEmail() + ')');
        }
    }
        //ฟังก์ชันนี้ใช้ในการสร้างผู้ใช้ใหม่
        public User createUser(User user) {
            checkDuplication(user); //เพื่อเช็คว่ามีผู้ใช้ที่มี username หรือ email ซ้ำกันหรือไม่
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            return userRepo.save(user);
        }

        //ฟังก์ชันนี้ใช้ในการสร้างผู้ใช้หลายคนในครั้งเดียว
        public List<User> createUsers(List<User> users) {
            for (User user : users) {
                checkDuplication(user); //เพื่อเช็คว่ามีผู้ใช้ที่มี username หรือ email ซ้ำกันหรือไม่
                user.setPassword(passwordEncoder.encode(user.getPassword()));
            }
            return userRepo.saveAll(users);
        }

        // week 9
        //Add authenticate()
        public Map<String, String> authenticateUser(JwtRequestUser user) {
            UsernamePasswordAuthenticationToken upat = new
                UsernamePasswordAuthenticationToken(
                user.getUsername(), user.getPassword());
            authenticationManager.authenticate(upat); //ส่งไปแล้ว ดึงauthenticationManager มาใช้

            //Exception occurred with (401) if failed
            UserDetails userDetails = jwtUserDetailsService
                    .loadUserByUsername(user.getUsername()); //ถ้าผ่่าน จะ load  user มาอีกรอบนึง

            //Add code week 9
            // 1000 คือ 1 วินาที | 60*1000 คือ 1 นาที | 60*60*1000 คือ 1 ชั่วโมง | 8*60*60*1000 คือ 8 ชั้วโมง
            long refreshTotokenAgeInMillisec = 8*60*60*1000; // 8 Hours
            return Map.of( //สามารถส่ง key value หลายอันได้
                    "access_token"
                    , jwtUtils.generateToken(userDetails),
                    "refresh_token"
                    , jwtUtils.generateToken(
                            userDetails, refreshTotokenAgeInMillisec, TokenType.REFRESH_TOKEN)
            );
    }

    //week 9
    public Map<String, Object> refreshToken(String refreshToken) {
        jwtUtils.verifyToken(refreshToken); //เช็คว่า token มันถูกต้องไหม(valid)

        //ดึงข้อมูลจาก Token (Claims)
        Map<String, Object> claims = jwtUtils.getJWTClaimsSet(refreshToken);
        jwtUtils.isExpired(claims); //เช็ค Expired

        //ตรวจสอบว่าค่า Claims ถูกต้อง และเป็น Refresh Token
        if (! jwtUtils.isValidClaims(claims) || ! "REFRESH_TOKEN".equals(claims.get("typ"))) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED
                    , "Invalid refresh token");
        }

        //ดึงข้อมูลผู้ใช้จากฐานข้อมูล
        UserDetails userDetails = jwtUserDetailsService.loadUserById((Long) claims.get("uid"));

        // ออก Access Token ใหม่
        return Map.of("access_token"
                , jwtUtils.generateToken(userDetails));
    }
}
