package top.focess.keystead.server.vault;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@Entity
@Table(name = "vault_members")
public class VaultMemberEntity {
    @EmbeddedId @NonNull VaultMemberEntityId id = new VaultMemberEntityId();

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    @NonNull VaultMemberRole role = VaultMemberRole.VIEWER;

    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false)
    @NonNull VaultMemberState state = VaultMemberState.INVITED;

    @Column(name = "created_at", nullable = false)
    @NonNull Instant createdAt = Instant.EPOCH;

    @Column(name = "updated_at", nullable = false)
    @NonNull Instant updatedAt = Instant.EPOCH;

    protected VaultMemberEntity() {}

    private VaultMemberEntity(@NonNull StoredVaultMember member) {
        this.id = new VaultMemberEntityId(member.vaultId(), member.userId());
        this.role = member.role();
        this.state = member.state();
        this.createdAt = member.createdAt();
        this.updatedAt = member.updatedAt();
    }

    static @NonNull VaultMemberEntity from(@NonNull StoredVaultMember member) {
        return new VaultMemberEntity(member);
    }

    @NonNull StoredVaultMember toStored() {
        return new StoredVaultMember(id.vaultId, id.userId, role, state, createdAt, updatedAt);
    }
}
