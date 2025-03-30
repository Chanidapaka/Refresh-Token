package sit.int204.jwtdemo.entities.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import sit.int204.jwtdemo.entities.entities.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    //ฟังก์ชันนี้ใช้เพื่อตรวจสอบว่ามีผู้ใช้ที่มี username หรือ email ที่ตรงกับค่าที่ส่งเข้าไปหรือไม่
    //boolean ที่คืนค่าจะเป็น true ถ้ามีผู้ใช้ที่มี username หรือ email ซ้ำ และ false หากไม่มี
    boolean existsUserByUsernameOrEmail(
            String username, String email
    );

    //@Query annotation เพื่อสร้าง JPQL (Java Persistence Query Language) คำสั่งเพื่อค้นหาผู้ใช้โดยใช้ทั้ง username หรือ email
    //ถ้าพบผู้ใช้ที่มี username หรือ email ที่ตรงกับค่าที่ส่งเข้าไป จะคืนค่า Optional<User> ที่ห่อหุ้ม User ที่ตรงกับเงื่อนไขนี้
    //โดย @Query ใช้คำสั่ง SQL แบบ JPQL (select u from User u where u.username=:usernameOrEmail
    //or u.email = :usernameOrEmail) เพื่อค้นหาผู้ใช้ในตาราง User โดยใช้เงื่อนไขตรงกับ username หรือ email
    @Query(value = "select u from User u where u.username=:usernameOrEmail or u.email = :usernameOrEmail")
        Optional<User> findByUsernameOrEmail(String usernameOrEmail);
}
