package com.soriole.wallet.sqrapp.litecoin;

import com.soriole.wallet.sqrapp.CryptoCurrency;
import com.soriole.wallet.sqrapp.bitcoin.Bitcoin;

public class Litecoin extends Bitcoin{
    public Litecoin(){
        this.networkVersion=(byte)0x30;
        this.privateKeyPrefix=(byte)0xb0;
    }
}
