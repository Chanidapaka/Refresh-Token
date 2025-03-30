package sit.int204.jwtdemo.entities.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Entity
@Table(name="users")
@Data
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(unique = true, nullable = false, length = 30)
    private String username;
    @Column(nullable = false, length = 255)
    private String password;
    @Column(length = 60)
    private String email;
    @Column(length = 40)
    private String name;
    @Column(length = 60)
    private String roles; //comma separate roles
}
