package com.soriole.wallet.sqrapp.stratis;

import com.soriole.wallet.sqrapp.CryptoCurrency;
import com.soriole.wallet.sqrapp.bitcoin.Bitcoin;

public class Stratis extends Bitcoin{
    public Stratis(){
        this.networkVersion=(byte)0x3f;
        this.privateKeyPrefix=(byte)0xbf;
    }
}
