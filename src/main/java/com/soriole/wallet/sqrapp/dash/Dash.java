package com.soriole.wallet.sqrapp.dash;

import com.soriole.wallet.sqrapp.CryptoCurrency;
import com.soriole.wallet.sqrapp.bitcoin.Bitcoin;

public class Dash extends Bitcoin{
    public Dash(){
        this.networkVersion=(byte)0x4c;
        this.privateKeyPrefix=(byte)0xcc;
    }
}
