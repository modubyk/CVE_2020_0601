rule cve_2020_0601_basePoint_equal_publicKey {

strings:

    $ecc_custom_params = { 06 07 2a 86 48 ce 3d 02 01 30 82 [2] 02 01 01 30 3c 06 07 2a 86 48 ce 3d 01 01 }

condition:

    for any x in (1..#ecc_custom_params):
        (for all i in
            (0..
                // Public Key Size
                uint8be(
                    @ecc_custom_params[1] // start at ecPublicKey OID
                    + uint16be(@ecc_custom_params[1] + 11)  // jump 11 bytes and resolve ecParameters sequence length tag
                    + 13 // jump 13 bytes to ecParameters sequence value content
                    + 1 // jump 1 bytes to bit string length tag
                ) - 3 // subtract 3 bytes (1 because iterator starts at 0, 1 for bit string unused bits header (0x00), 1 for unused byte
            ) :
                (
                    uint16be(
                        @ecc_custom_params[1] // start at ecPublicKey OID
                        + uint16be(@ecc_custom_params[1] + 11)  // jump 11 bytes and resolve ecParameters sequence length tag
                        + 13 // jump 13 bytes to ecParameters sequence value content
                        + 3 // jump 3 bytes past bit string type length header to value content
                        + i
                    )
                    ==
                    uint16be(
                        @ecc_custom_params[1] // start at ecPublicKey OID
                        + 20 // jump 20 bytes to FieldID value content
                        + uint8be(@ecc_custom_params[1] + 17) // resolve and jump FieldID object Length
                        + ( // resolve and jump Curve object length
                            uint8be (
                                @ecc_custom_params[1] // start at ecPublicKey OID
                                + 19 // jump 19 bytes to FieldID length tag
                                + uint8be(@ecc_custom_params[1] + 17)  // resolve FieldID object Length
                            )
                        )
                        + 2 // jump 2 bytes past octet string type length header to value content
                        + i
                    )

                )
       )
}