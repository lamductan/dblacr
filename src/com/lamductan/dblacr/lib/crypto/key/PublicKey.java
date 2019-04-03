package com.lamductan.dblacr.lib.crypto.key;

import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.util.Arrays;
import java.util.Date;

import java.util.logging.Logger;
import java.util.logging.Level;

import com.ibm.zurich.idmx.utils.GroupParameters;
import com.ibm.zurich.idmx.utils.StructureStore;
import com.ibm.zurich.idmx.utils.SystemParameters;
import com.ibm.zurich.idmx.utils.Utils;
import com.lamductan.dblacr.lib.utils.AuxUtils;
import com.lamductan.dblacr.system.DBLACRSystem;

/**
 * The 's public key for the CL-signature scheme. In addition to the key
 * itself, this object also contains the epochLength (which defines intervals
 * when credentials expire), and a unique identifier to identify the key.
 *
 * @see PrivateKey
 * @see KeyPair
 */
public final class PublicKey implements IPublicKey, Serializable{


    /**
     *
     */
    private static final long serialVersionUID = 2130192696934134618L;

    /** Logger. */
    private static Logger log = Logger.getLogger(PublicKey.class
            .getName());

    /** Location of the group parameters corresponding to this key. */
    private URI groupParametersLocation;
    private GroupParameters gp;

    /** <tt>S</tt> as specified in ... */
    private final BigInteger capS;
    /** <tt>Z</tt> as specified in ... */
    private final BigInteger capZ;
    /** Bases for the messages. */
    private final BigInteger[] capR;
    /** Modulus. */
    private final BigInteger N;
    /** Length of an epoch. */
    private final int epochLength;

    /** Modulus of all computation **/
    private final BigInteger g;
    private final BigInteger h;
    private final BigInteger Modulus;

    private final BigInteger n1;
    private final BigInteger h1;
    private final BigInteger h2;

    public PublicKey(SystemParameters sp, GroupParameters _gp, final PrivateKey privKey,
              final int nbrOfAttrs, final int theEpochLength) {

        if (privKey == null || nbrOfAttrs < sp.getL_res()) {
            throw new IllegalArgumentException();
        }

        if (theEpochLength < 1) {
            // case when no epoch is used
            log.log(Level.FINE, "No epoch used in  public key.");
            epochLength = 0;
        } else {
            epochLength = theEpochLength;
        }
        gp = _gp;

        log.log(Level.INFO, "Generating public key");
        Date start = new Date();

        N = privKey.getN();
        capS = Utils.computeGeneratorQuadraticResidue(privKey.getN(), sp);

        // p'*q'
        final BigInteger productPQprime = privKey.getPPrime().multiply(
                privKey.getQPrime());

        // upper = p'q'-1 - 2
        final BigInteger upper = productPQprime.subtract(BigInteger.ONE)
                .subtract(Utils.TWO);
        // capZ: rand num range [2 .. p'q'-1]. we pick capZ in [0..upper] and
        // then add 2.
        final BigInteger x_Z = Utils.computeRandomNumber(upper, sp).add(
                Utils.TWO);
        capZ = capS.modPow(x_Z, privKey.getN());

        // capR[]
        capR = new BigInteger[nbrOfAttrs];
        for (int i = 0; i < nbrOfAttrs; i++) {
            // pick x_R as rand num in range [2 .. p'q'-1]
            final BigInteger x_R = Utils.computeRandomNumber(upper, sp).add(
                    Utils.TWO);
            capR[i] = capS.modPow(x_R, privKey.getN());
        }

        Date stop = new Date();

        log.log(Level.INFO, "\nIssuePublicKey: start: " + start.toString()
                + " end: " + stop.toString());

        Modulus = DBLACRSystem.getModulus();
        g = Utils.computeGeneratorQuadraticResidue(Modulus, sp);
        h = Utils.computeGeneratorQuadraticResidue(Modulus, sp);

        n1 = AuxUtils.computeModulus(sp);
        h1 = Utils.computeGeneratorQuadraticResidue(n1, sp);
        h2 = Utils.computeGeneratorQuadraticResidue(n1, sp);
    }

    /**
     * @return Group parameters.
     */
    public GroupParameters getGroupParams() {
        return gp;
    }

    /**
     * @return Group parameters location.
     */
    public final URI getGroupParamsLocation() {
        return groupParametersLocation;
    }

    /**
     * @return True if this PublicKey has the epoch length field set.
     */
    public boolean hasEpoch() {
        if (epochLength > 0) {
            return true;
        }

        return false;
    }

    /**
     * @return Epoch length (in seconds) if this public key has the epoch field
     *         set. If not, an {@link IllegalArgumentException} is thrown.
     */
    public int getEpochLength() {
        if (!hasEpoch()) {
            throw new IllegalArgumentException("Requesting epochLength from "
                    + "PublicKey which dosen't have one.");
        }
        return epochLength;
    }

    /**
     * @return Current epoch. Computes an integer value representing the current
     *         epoch. The current epoch is computed as floor(
     *         currentTime/epochLength), where the currentTime and epochLength
     *         are in seconds.
     */
    public BigInteger computeCurrentEpoch() {
        double localEpochLength = (double) getEpochLength();
        double currentTime = ((double) System.currentTimeMillis()) / 1000.0;
        BigInteger currentEpoch = BigInteger.valueOf((long) Math
                .floor(currentTime / localEpochLength));
        return currentEpoch;
    }

    /**
     * @return Number of attributes which may be signed by this public key. (the
     *         dimension of the message space in the CL signature scheme)
     */
    public int getMaxNbrAttrs() {
        return capR.length;
    }

    /**
     * @return Randomization base <tt>S</tt>.
     */
    public BigInteger getCapS() {
        return capS;
    }

    /**
     * @return Signature element <tt>Z</tt>.
     */
    public BigInteger getCapZ() {
        return capZ;
    }

    /**
     * @return Array of attribute bases <tt>R_i</tt>.
     */
    public BigInteger[] getCapR() {
        return capR;
    }

    /**
     * @return Modulus <tt>n</tt>.
     */
    public BigInteger getN() {
        return N;
    }

    public BigInteger getModulus() {return Modulus;}

    /**
     * @return Human-readable description of this object.
     */
    public String toStringPretty() {
        String endl = System.getProperty("line.separator");
        String s = "'s public key: " + endl;
        s += "\tNumber of bases: " + capR.length + endl;
        s += "\tn, capS, capZ : " + Utils.logBigInt(N) + ", "
                + Utils.logBigInt(capS) + ", " + Utils.logBigInt(capZ) + endl;
        s += "\tR[" + 0 + "..." + (capR.length - 1) + "]: ";
        for (int i = 0; i < capR.length; i++) {
            s += Utils.logBigInt(capR[i]);
            if (i < capR.length - 1) {
                s += ", ";
            }
        }

        return s;
    }

    @Override
    public boolean equals(final Object o) {
        if (o == null) {
            return false;
        }
        if (!(o instanceof PublicKey)) {
            return false;
        }

        PublicKey ikp = (PublicKey) o;
        if (this == ikp) {
            return true;
        }
        return (capS.equals(ikp.capS) && capZ.equals(ikp.capZ)
                && N.equals(ikp.N) && Arrays.equals(capR, ikp.capR));
    }

    @Override
    public int hashCode() {
        int tempHashCode = 0;
        tempHashCode += capS.hashCode();
        tempHashCode += capZ.hashCode();
        tempHashCode += N.hashCode();
        tempHashCode += capR.hashCode();
        return tempHashCode;
    }

    public BigInteger generateHash() {
        BigInteger[] items = new BigInteger[3 + capR.length];
        items[0] = capS;
        items[1] = capZ;
        items[2] = N;
        for(int i = 0; i < capR.length;++i) {
            items[i+3] = capR[i];
        }

        return Utils.hashOf(256, items);
    }

    public BigInteger getG() {return g;}
    public BigInteger getH() {return h;}
    public BigInteger getN1() {return n1;}
    public BigInteger getH1() {return h1;}
    public BigInteger getH2() {return h2;}
}

