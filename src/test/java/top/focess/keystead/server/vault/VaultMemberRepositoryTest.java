package top.focess.keystead.server.vault;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest
@ActiveProfiles("test")
class VaultMemberRepositoryTest {

    @Autowired private VaultService vaultService;
    @Autowired private VaultMemberRepository members;

    @Test
    void creatingVaultCreatesActiveOwnerMembership() {
        vaultService.put("member-owner", "member-vault", new VaultRequest("opaque-metadata"));

        StoredVaultMember member = members.find("member-vault", "member-owner").orElseThrow();
        assertEquals(VaultMemberRole.OWNER, member.role());
        assertEquals(VaultMemberState.ACTIVE, member.state());
    }
}
