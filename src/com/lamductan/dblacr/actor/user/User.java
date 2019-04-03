package com.lamductan.dblacr.actor.user;

import com.ibm.zurich.idmx.dm.Nym;
import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.actor.Actor;
import com.lamductan.dblacr.lib.blockchain.AuthenticationRecord;
import com.lamductan.dblacr.lib.blockchain.BlockchainObject;
import com.lamductan.dblacr.lib.blockchain.RegistrationRecord;
import com.lamductan.dblacr.lib.blockchain.Requirement;
import com.lamductan.dblacr.lib.crypto.key.PrivateKey;
import com.lamductan.dblacr.lib.crypto.key.PublicKey;
import com.lamductan.dblacr.lib.crypto.proof.IProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.authenticationCommon.AuthenticationProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.FullFilmentPolicyProof;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.fullfilmentPolicy.FullfilmentPolicySPKProver;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.registration.PossessKeySPKProver;
import com.lamductan.dblacr.lib.crypto.proof.SPK.common.TreeMapProof;
import com.lamductan.dblacr.actor.sp.ServiceProvider;
import com.lamductan.dblacr.lib.crypto.proof.SPK.spk.authentication.ticketValidation.TicketValidateSPKProver;
import com.lamductan.dblacr.lib.crypto.ticket.Ticket;
import com.lamductan.dblacr.system.DBLACRSystem;

import java.io.Serializable;
import java.math.BigInteger;

public class User extends Actor implements Serializable {
    private static final long serialVersionUID = 6529685098267757697L;

    private PrivateKey privateKey = null;
    private PublicKey publicKey = null;
    SystemParameters sp = DBLACRSystem.getInstance().getSystemParameters();
    GroupParameters gp = DBLACRSystem.getInstance().getGroupParamters();
    BigInteger context = DBLACRSystem.getInstance().getContext();

    public PublicKey getPublicKey() {return publicKey;}
    public PrivateKey getPrivateKey() {return privateKey;} //TODO: remove this function for security

    public User() {super();}


    /** Register Phase **/
    public boolean register() {
        if (privateKey == null || publicKey == null) {
            long startTime = System.currentTimeMillis();
            privateKey = new PrivateKey(sp);
            long endPrivKeyGen = System.currentTimeMillis();
            System.out.println("Generate privkey in " +
                    1.0 * (endPrivKeyGen - startTime) / 1000 + "s");
            publicKey = new PublicKey(sp, gp, privateKey, 1, 0);
            privateKey.setPublicKey(publicKey);
            long endTime = System.currentTimeMillis();
            System.out.println("Generate pubkey in " +
                    1.0 * (endTime - endPrivKeyGen) / 1000 + "s");
        }
        Nym nym = new Nym(gp, publicKey.getN(), "nym");
        BigInteger nonce = Utils.computeRandomNumberSymmetric(sp.getL_m());
        IProof proof = createRegistrationProof(nonce);
        BlockchainObject registrationRecord = new RegistrationRecord(nym, publicKey, proof);
        pushRegistrationRecord(registrationRecord);

        return verifyRegistrationProof(registrationRecord, nonce);
    }

    public IProof createRegistrationProof(BigInteger nonce) {
        PossessKeySPKProver possessKeySPK = new PossessKeySPKProver(
                sp, gp, privateKey, publicKey, nonce);
        TreeMapProof proof = possessKeySPK.buildProof();
        return proof;
    }

    public void pushRegistrationRecord(BlockchainObject registrationRecord) {
        super.pushToSystem(registrationRecord);
        dblacrSystem.getUsers().add(this);
    }

    /** End Register Phase **/


    /** Authentication Phase **/
    public boolean authenticate(int sid) {
        ServiceProvider sp = dblacrSystem.getServiceProviderBySid(sid);
        Requirement requirement = sp.putRequirement();
        boolean checkRequirementResult = checkRequirement(requirement);
        if (!checkRequirementResult) {
            System.out.println("User not satisfy requirement.");
            return false;
        }

        BigInteger challenge = sp.computeChallenge();
        if (!checkChallenge(challenge, sid)) {
            System.out.println("Invalid challenge");
            return false;
        }

        Ticket tau1 = new Ticket(privateKey);
        IProof authenticationProof = createAuthenticationProof(tau1, requirement, challenge);
        int newAuthenticationId = dblacrSystem.getNewAuthenticationId();
        BlockchainObject authenticationRecord = new AuthenticationRecord(
                newAuthenticationId, sid, tau1, publicKey, authenticationProof);
        pushToSystem(authenticationRecord);

        return verifyAuthenticationRecord(authenticationRecord, challenge, requirement);
    }

    private boolean checkChallenge(BigInteger challenge, int sid) {
        return true;
    }
    private boolean checkRequirement(Requirement requirement) {
        return true;
    }


    private IProof createAuthenticationProof(Ticket tau1, Requirement requirement, BigInteger challenge) {
        long startTime = System.currentTimeMillis();
        TicketValidateSPKProver ticketValidateSPK = new TicketValidateSPKProver(
                sp, gp, privateKey, publicKey, challenge, tau1, requirement);
        TreeMapProof ticketValidateProof = ticketValidateSPK.buildProof();

        FullfilmentPolicySPKProver fullfilmentPolicySPKProver = new FullfilmentPolicySPKProver(
                sp, gp, privateKey, publicKey, tau1, requirement);
        FullFilmentPolicyProof fullfilmentPolicyProof = fullfilmentPolicySPKProver
                .buildFullFilmentPolicyProof();
        AuthenticationProof authenticationProof = new AuthenticationProof(
                ticketValidateProof, fullfilmentPolicyProof);
        long endTime = System.currentTimeMillis();
        System.out.println("Generate Authenticate Proof in " + (endTime - startTime)*1.0/1000 + "s");
        return authenticationProof;
    }
    /** End Authentication Phase **/
}
