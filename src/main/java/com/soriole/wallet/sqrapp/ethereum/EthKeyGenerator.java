package com.soriole.wallet.sqrapp.ethereum;

import com.soriole.wallet.lib.KeyGenerator;
import org.bouncycastle.asn1.sec.SECNamedCurves;

public class EthKeyGenerator extends KeyGenerator{

    public EthKeyGenerator(){
        super(SECNamedCurves.getByName("secp256k1"), "Ethereum seed");
    }



}
