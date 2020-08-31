package academy.devdojo.core.model;

import lombok.*;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public class ApplicationUser implements AbstractEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;
    @NotBlank(message = "O Username é obrigatorio")
    @Column(nullable = false)
    private String username;
    @NotBlank(message = "O Password é obrigatorio")
    @Column(nullable = false)
    @ToString.Exclude
    private String password;
    @NotBlank(message = "O Role é obrigatorio")
    @Column(nullable = false)
    private String role = "USER";

    public ApplicationUser(@NotNull ApplicationUser applicationUser) {
        this.id = applicationUser.getId();
        this.username = applicationUser.getUsername();
        this.password = applicationUser.getPassword();
        this.role = applicationUser.getRole();
    }
}
